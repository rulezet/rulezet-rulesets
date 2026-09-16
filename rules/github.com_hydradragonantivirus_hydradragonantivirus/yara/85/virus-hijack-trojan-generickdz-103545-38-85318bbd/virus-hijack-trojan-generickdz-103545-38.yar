rule Virus_Hijack_Trojan_GenericKDZ_103545_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a3575f5e3c19d3b2c401078a26ddc54e10cc4bac858e9bd1dbb2520c3c01c36"

  strings:
    $s1 = "{software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}