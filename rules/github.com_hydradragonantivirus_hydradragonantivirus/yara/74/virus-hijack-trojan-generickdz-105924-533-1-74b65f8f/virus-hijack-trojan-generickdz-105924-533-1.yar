rule Virus_Hijack_Trojan_GenericKDZ_105924_533_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_533_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12680d389deeda5b8fdebfc7fc1a4631193e2897ffef144253e840d0ef7cdce8"

  strings:
    $s1 = "HOrY&]f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}