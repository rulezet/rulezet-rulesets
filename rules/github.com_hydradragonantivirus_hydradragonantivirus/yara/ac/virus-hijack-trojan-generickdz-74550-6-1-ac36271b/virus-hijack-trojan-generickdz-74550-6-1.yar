rule Virus_Hijack_Trojan_GenericKDZ_74550_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67cc55928d37b98383ff4967f01dd7706fbf6177f0857953592c2a512a62f63a"

  strings:
    $s1 = "GATA eLh" fullword ascii
    $s2 = "tRoW%8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}