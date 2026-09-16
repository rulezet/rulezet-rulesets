rule Trojan_Autorun_Trojan_GenericKDZ_101457_8 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.101457_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2c6a6cf342c55e6cd58a1a7f8d2db60c43eb76ece37a9fbdb3afcb30be19dde"

  strings:
    $s1 = "BegO:e5o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}