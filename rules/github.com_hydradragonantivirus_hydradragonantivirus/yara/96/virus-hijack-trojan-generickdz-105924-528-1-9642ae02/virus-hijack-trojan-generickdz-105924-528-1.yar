rule Virus_Hijack_Trojan_GenericKDZ_105924_528_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_528_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "342a4224ee889a68a6191bc245ee1cc49f5fb26fc0e797b0ac70f71fad5f6a87"

  strings:
    $s1 = "t cUSK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}