rule Virus_Hijack_Trojan_GenericKDZ_103285_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec4935830b85e4141b4847702a363cc10e69788ee76542390956f6b283cb22f6"

  strings:
    $s1 = "LComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}