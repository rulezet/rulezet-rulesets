rule Virus_Hijack_Trojan_GenericKDZ_105924_356_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_356_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a018374970ab2a207da4dcd206ff560c27771ad373543e5f5b6a29db75284563"

  strings:
    $s1 = "~]bEAR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}