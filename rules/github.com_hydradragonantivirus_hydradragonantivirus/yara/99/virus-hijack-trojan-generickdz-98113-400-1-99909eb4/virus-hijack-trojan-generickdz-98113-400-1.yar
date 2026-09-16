rule Virus_Hijack_Trojan_GenericKDZ_98113_400_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_400_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f473862f6ecebf87df721b926baa4d1796ed70d78647cf1624997d3a73f7e78"

  strings:
    $s1 = "A+P&oARED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}