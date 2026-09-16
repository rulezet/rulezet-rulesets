rule Virus_Hijack_Trojan_GenericKDZ_99416_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50f763412ac7f05310592cd41d208dd49163b10fa9e67cf4e0edac32a563af56"

  strings:
    $s1 = "pUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}