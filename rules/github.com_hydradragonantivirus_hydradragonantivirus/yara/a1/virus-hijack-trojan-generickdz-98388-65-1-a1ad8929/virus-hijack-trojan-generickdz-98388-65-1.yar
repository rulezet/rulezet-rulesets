rule Virus_Hijack_Trojan_GenericKDZ_98388_65_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa2bce7b8d0ece57513adfeeaeb7a6b628bacd386d8518eb8c7828a0b93b90ca"

  strings:
    $s1 = "\"BusT`" fullword ascii
    $s2 = "D)@dOte" fullword ascii
    $s3 = "<'[/\"FLeD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}