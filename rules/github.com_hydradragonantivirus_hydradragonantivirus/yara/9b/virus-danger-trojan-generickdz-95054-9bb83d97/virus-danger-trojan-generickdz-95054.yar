rule Virus_Danger_Trojan_GenericKDZ_95054 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.95054.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39b780276fab1075961208d4e67b3d2c40d9a8f24c5c6ede04562354c945737c"

  strings:
    $s1 = "8V*sion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}