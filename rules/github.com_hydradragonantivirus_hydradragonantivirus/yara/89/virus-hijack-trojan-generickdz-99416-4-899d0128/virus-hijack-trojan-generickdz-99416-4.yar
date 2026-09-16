rule Virus_Hijack_Trojan_GenericKDZ_99416_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c4252d31e51966a4408d687d7be2d20933fc234b0af1dbf91458de2904935ad"

  strings:
    $s1 = "!User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}