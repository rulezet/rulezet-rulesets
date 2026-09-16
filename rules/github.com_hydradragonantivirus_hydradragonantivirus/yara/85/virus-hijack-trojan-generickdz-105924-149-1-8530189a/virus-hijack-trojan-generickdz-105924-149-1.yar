rule Virus_Hijack_Trojan_GenericKDZ_105924_149_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba80e9f76390bcef1a6d1ec98a95902c9cf0d62f892d4aeacc2c14a3df9305e"

  strings:
    $s1 = "windows media player.exe" fullword wide
    $s2 = "lenO}r:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}