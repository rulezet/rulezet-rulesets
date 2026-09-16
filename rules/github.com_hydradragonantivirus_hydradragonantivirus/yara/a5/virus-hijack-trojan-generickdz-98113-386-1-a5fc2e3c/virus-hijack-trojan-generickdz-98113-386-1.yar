rule Virus_Hijack_Trojan_GenericKDZ_98113_386_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_386_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01b7399df8735e5d6190a118445e6b11668d489ed9ccfb98d0fff265decd8b4d"

  strings:
    $s1 = "2\"FLeD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}