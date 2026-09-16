rule Virus_Hijack_Trojan_GenericKDZ_74550_372_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_372_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdd749333a86f2d172bff5407ba264c04a191acfdc711f8b5f3d42712922ea45"

  strings:
    $s1 = "viLa)^." fullword ascii
    $s2 = "g*<BUnG" fullword ascii
    $s3 = "\"(koae" fullword ascii
    $s4 = "FEEd}=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}