rule Virus_Hijack_Trojan_GenericKDZ_98113_291_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_291_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19a1eef27a09263459c0b148a696eee92d944f94599991dd2f9c106498ea9cc5"

  strings:
    $s1 = "3$raIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}