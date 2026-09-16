rule Trojan_Danger_Trojan_GenericKD_67269844_39_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4992fc9381c1f2aa759be05a41b24f176368da7f9bb8dba584c9b9b623e07f0a"

  strings:
    $s1 = "Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}