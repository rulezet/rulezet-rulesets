rule Virus_Hijack_Trojan_GenericKDZ_98113_289_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_289_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b04f923ec6744dbcf2e1a501988db3c23ed6bc9542205d9a4da2c4b85b328ca5"

  strings:
    $s1 = "lInO?Na\"" fullword ascii
    $s2 = "TALK`$" fullword ascii
    $s3 = "waRL[G" fullword ascii
    $s4 = "^TZ:WESt>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}