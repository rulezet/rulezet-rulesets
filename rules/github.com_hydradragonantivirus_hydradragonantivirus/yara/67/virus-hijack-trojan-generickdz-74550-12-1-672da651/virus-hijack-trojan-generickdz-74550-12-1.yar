rule Virus_Hijack_Trojan_GenericKDZ_74550_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32b0840f37521ab25e56fef9ab900fbf88c0e523067817afd49eda6fe532f6d5"

  strings:
    $s1 = "6( JYNX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}