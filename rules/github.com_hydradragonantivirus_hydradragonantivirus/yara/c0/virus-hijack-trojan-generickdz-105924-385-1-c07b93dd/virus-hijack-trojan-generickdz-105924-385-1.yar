rule Virus_Hijack_Trojan_GenericKDZ_105924_385_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_385_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e3a13d0e48e5fbf425d5b9cf3f4ce4932dc47fb1c7b71f67ed974348f8312a8"

  strings:
    $s1 = "r(TOUT" fullword ascii
    $s2 = "@(TODE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}