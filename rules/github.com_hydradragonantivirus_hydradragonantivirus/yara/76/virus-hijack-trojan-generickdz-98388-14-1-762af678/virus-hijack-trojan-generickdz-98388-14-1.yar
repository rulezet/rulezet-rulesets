rule Virus_Hijack_Trojan_GenericKDZ_98388_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0893b1d92d5e38f41af7c1912b8950c7586b04c7c37f117807250714759d7e2"

  strings:
    $s1 = "\"O*gerb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}