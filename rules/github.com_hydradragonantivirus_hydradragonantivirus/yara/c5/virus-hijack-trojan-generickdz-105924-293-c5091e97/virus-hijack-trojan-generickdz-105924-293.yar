rule Virus_Hijack_Trojan_GenericKDZ_105924_293 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_293.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24b5bf5c7979eb4d8ff3718d7eaaa7254875865ac6d625cf5743d834e3f03bd7"

  strings:
    $s1 = "N,EmYD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}