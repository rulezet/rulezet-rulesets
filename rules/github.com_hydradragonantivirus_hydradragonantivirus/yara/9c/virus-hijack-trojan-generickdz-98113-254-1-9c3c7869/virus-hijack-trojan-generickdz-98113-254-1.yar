rule Virus_Hijack_Trojan_GenericKDZ_98113_254_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_254_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abb8789e3e0af49634d9e646e987defefe873914b7c4630d3a054620d21fd5e8"

  strings:
    $s1 = "DAtE%]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}