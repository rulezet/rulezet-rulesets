rule Virus_Hijack_Trojan_GenericKDZ_99416_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bbb60b9ee6594aa43ba94ed03dbcbe867c564f9cb11d04c23eb1fa78332f80b"

  strings:
    $s1 = "JUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}