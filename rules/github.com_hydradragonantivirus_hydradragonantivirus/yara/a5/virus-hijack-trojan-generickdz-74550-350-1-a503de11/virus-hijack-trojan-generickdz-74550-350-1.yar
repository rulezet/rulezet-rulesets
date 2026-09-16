rule Virus_Hijack_Trojan_GenericKDZ_74550_350_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_350_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "330fcbf277a9e17d5b36bb3400bbfba974ec5d984ef4a52263eedad1cb76703c"

  strings:
    $s1 = "tIDy@B*" fullword ascii
    $s2 = "Ream@ " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}