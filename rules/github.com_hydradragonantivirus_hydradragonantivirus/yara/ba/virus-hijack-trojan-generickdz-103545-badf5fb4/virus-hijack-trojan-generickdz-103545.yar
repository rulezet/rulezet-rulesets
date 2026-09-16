rule Virus_Hijack_Trojan_GenericKDZ_103545 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eadb0df51287dcb8fb11f70b3fa7c4da65101888562cda2cae7debd0837b7e4"

  strings:
    $s1 = "(software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii
    $s2 = "MALI:yqi*i5k(/KC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}