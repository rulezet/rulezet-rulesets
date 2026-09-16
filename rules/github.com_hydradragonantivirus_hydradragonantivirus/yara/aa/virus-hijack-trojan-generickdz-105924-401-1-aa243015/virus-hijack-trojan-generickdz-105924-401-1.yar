rule Virus_Hijack_Trojan_GenericKDZ_105924_401_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_401_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7cb6f83ff3b59d320de39428637f9222f909d07b86488fdf5e640fba6bf46a9"

  strings:
    $s1 = "J)sOpH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}