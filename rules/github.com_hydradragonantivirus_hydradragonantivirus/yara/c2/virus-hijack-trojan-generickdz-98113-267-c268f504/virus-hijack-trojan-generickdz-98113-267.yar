rule Virus_Hijack_Trojan_GenericKDZ_98113_267 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_267.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d63406188f36006ba84c99a3a5229ef0a2a3096b26845247dcdc22947a3ae1e"

  strings:
    $s1 = "K|or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}