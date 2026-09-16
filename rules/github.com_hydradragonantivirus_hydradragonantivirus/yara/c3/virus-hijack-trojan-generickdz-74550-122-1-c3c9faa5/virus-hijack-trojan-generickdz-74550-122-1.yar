rule Virus_Hijack_Trojan_GenericKDZ_74550_122_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_122_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4542932d1bafe4b946c843fe7981d54dccf0ed13a9d5e4980f7909132d308b43"

  strings:
    $s1 = "yawl.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}