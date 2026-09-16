rule Virus_Hijack_Trojan_GenericKDZ_74550_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74330e7baba495498c3d162de5c156dfea22a2f339c039bd1905a253265ab3fe"

  strings:
    $s1 = "GErS'>@8" fullword ascii
    $s2 = "TUwi>E?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}