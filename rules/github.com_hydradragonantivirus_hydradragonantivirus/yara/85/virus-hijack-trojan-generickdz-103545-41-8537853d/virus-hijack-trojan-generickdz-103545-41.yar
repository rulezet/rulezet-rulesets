rule Virus_Hijack_Trojan_GenericKDZ_103545_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3969f01a0f70d2ddceae7d7524b5bae1b75aa59e3cd420b00c3a852ff55dcaa"

  strings:
    $s1 = "6software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}