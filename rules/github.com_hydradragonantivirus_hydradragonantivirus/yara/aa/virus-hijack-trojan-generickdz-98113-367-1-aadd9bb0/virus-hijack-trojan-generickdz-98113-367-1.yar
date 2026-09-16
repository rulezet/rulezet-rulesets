rule Virus_Hijack_Trojan_GenericKDZ_98113_367_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_367_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ede1f699408105cfae532a97c50e3661d17d307f1882017dfcd2e2e2c7bf5feb"

  strings:
    $s1 = "boID@d?]" fullword ascii
    $s2 = "lOre;N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}