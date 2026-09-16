rule Virus_Hijack_Trojan_GenericKDZ_105924_440_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_440_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49fae5c4c12977302ebf1a4f523a9b308b0a5a907146f9acc3420dbdb43c1018"

  strings:
    $s1 = "vo#BOTt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}