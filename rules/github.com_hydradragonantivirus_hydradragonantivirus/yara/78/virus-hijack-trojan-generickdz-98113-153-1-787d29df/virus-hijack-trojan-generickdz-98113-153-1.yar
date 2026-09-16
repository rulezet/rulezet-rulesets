rule Virus_Hijack_Trojan_GenericKDZ_98113_153_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63033f3553aaf610bac956de76d7a756dc1f2e78fbfde550e55daf03804700d9"

  strings:
    $s1 = "baSH#!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}