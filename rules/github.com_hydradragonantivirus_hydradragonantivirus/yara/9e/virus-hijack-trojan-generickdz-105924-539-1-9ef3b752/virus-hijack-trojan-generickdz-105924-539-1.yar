rule Virus_Hijack_Trojan_GenericKDZ_105924_539_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_539_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af89e8d6351336ef9b06877e7b72152cb71eafff62b23b0024d1f2dd39117af"

  strings:
    $s1 = "sark*a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}