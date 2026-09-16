rule Virus_Hijack_Trojan_GenericKDZ_103285_183 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_183.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1b278a287a21e4a1e6cb5bbb59217cd4cb19d068b2c12d35b518b5551e5cc2a"

  strings:
    $s1 = "Gremainder of Section B remaining in full force and effect." fullword ascii
    $s2 = "AedN@etNA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}