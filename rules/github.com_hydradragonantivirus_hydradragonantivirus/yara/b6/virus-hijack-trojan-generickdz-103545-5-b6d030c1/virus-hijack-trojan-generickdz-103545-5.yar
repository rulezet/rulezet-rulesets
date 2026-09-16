rule Virus_Hijack_Trojan_GenericKDZ_103545_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45cb2402e01cb2db4fbac1ce6553cf0fe18197d9dffdb466876412bd49f3b695"

  strings:
    $s1 = "dsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}