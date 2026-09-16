rule Virus_Hijack_Trojan_GenericKDZ_105930_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "945f2a822f3d3bfdfc86df5c29cd2fd80ecd7b944b19812aa3957af809e81f6b"

  strings:
    $s1 = "P)geal]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}