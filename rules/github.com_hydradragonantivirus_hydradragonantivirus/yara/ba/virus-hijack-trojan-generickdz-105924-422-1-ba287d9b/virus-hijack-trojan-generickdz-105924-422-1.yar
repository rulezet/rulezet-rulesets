rule Virus_Hijack_Trojan_GenericKDZ_105924_422_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_422_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff531b1ee414ba942e663224ed33d4350ffed4817fffedbc14d66d03aeb396f0"

  strings:
    $s1 = "Tg8Z)SnAb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}