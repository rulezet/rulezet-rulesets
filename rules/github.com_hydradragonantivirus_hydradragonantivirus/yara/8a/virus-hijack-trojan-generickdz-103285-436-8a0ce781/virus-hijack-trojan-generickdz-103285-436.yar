rule Virus_Hijack_Trojan_GenericKDZ_103285_436 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_436.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c561b8a616cf1f3ced512ade65fd00b8e70e501fbf172819cd9670593aeaeb"

  strings:
    $s1 = "J}SaIp" fullword ascii
    $s2 = "#\"SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}