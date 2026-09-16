rule Virus_Hijack_Trojan_GenericKDZ_105924_364_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_364_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "833561c26097edc7df87f21f7649208252fc24140bb6a2cd70c6a986746abd17"

  strings:
    $s1 = "pHOS?Wm[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}