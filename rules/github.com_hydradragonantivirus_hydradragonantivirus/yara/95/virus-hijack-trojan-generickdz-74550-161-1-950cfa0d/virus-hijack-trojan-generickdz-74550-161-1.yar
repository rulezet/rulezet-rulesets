rule Virus_Hijack_Trojan_GenericKDZ_74550_161_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_161_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "157126dd3bfc89de882dbc8f68ef67fe4a05a721875adb63f626d36f3327a0b5"

  strings:
    $s1 = "D*rUnt%!" fullword ascii
    $s2 = "STIm(/" fullword ascii
    $s3 = "y?NiGH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}