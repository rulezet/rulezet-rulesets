rule Virus_Hijack_Trojan_GenericKDZ_74550_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66937cde692de86875fcf76b24e59651f089ac80d2f01c288581c54ae9bfb0b3"

  strings:
    $s1 = "O;GoaT" fullword ascii
    $s2 = "TInK$#" fullword ascii
    $s3 = "MaGe$I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}