rule Virus_Hijack_Trojan_GenericKDZ_98388_195_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_195_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38bf797d6540969c8829b6865cb9d710730d734bddb5cc665e5507f3daee99e"

  strings:
    $s1 = "(,FAge" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}