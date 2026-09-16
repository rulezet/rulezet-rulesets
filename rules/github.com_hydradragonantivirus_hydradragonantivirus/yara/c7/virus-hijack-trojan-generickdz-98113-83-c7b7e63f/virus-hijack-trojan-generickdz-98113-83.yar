rule Virus_Hijack_Trojan_GenericKDZ_98113_83 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "623aeae78b8d6e6454b2a6cca6da72914afad21a9e4589e59d5596a3637bdb2a"

  strings:
    $s1 = "u&*buL*buNK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}