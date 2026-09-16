rule Virus_Hijack_Trojan_GenericKDZ_74550_88_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7576c4b0d07b1994f15c630b401d828c7ca954ff65724da47d2e7b3fe58c26ec"

  strings:
    $s1 = "k4#PURL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}