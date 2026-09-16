rule Virus_Hijack_Trojan_GenericKDZ_103285_649 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_649.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "557328bd507ff964c07d07ba4824fb93f6fce9a9958b386d58ef247b1eb267d4"

  strings:
    $s1 = "21a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}