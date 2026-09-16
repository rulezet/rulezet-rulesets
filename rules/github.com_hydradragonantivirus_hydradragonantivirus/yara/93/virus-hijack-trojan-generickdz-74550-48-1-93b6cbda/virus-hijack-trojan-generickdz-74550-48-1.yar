rule Virus_Hijack_Trojan_GenericKDZ_74550_48_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf593e0fdf6fa20ae8937cdce4c9a946391f4d65e30e5cf6c0c51631d6ef2c25"

  strings:
    $s1 = "TECK?vQ" fullword ascii
    $s2 = "AmBA>J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}