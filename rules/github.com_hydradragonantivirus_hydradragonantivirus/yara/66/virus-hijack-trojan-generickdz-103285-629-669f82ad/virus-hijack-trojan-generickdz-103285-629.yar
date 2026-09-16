rule Virus_Hijack_Trojan_GenericKDZ_103285_629 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_629.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6baed8c5816c6d7b2377c8a8a8da815c07a341950ce444bb6ad90105a9d2917e"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}