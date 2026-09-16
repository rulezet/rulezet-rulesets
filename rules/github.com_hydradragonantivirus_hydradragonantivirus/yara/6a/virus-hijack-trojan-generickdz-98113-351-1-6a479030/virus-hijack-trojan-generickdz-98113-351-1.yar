rule Virus_Hijack_Trojan_GenericKDZ_98113_351_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_351_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36417a157ba50103b551c55c44377105455f7d3f76add8d0ffe3859ae32bfe64"

  strings:
    $s1 = "2#cLIt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}