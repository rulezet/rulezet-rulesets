rule Virus_Hijack_Trojan_GenericKDZ_103285_467 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_467.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ff5c4c4dfb5909ffac451ef9501ee207b49095960240700f94391c923b530b3"

  strings:
    $s1 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}