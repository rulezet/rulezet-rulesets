rule Virus_Sysbot_Trojan_GenericKDZ_94923_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fc970a90cb2ab6afb07c3dcbbf7b30986d96858a258951937d2fd3131b842b3"

  strings:
    $s1 = "Win Mixer" fullword wide
    $s2 = "P@ZEED" fullword ascii
    $s3 = "HoJU@E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}