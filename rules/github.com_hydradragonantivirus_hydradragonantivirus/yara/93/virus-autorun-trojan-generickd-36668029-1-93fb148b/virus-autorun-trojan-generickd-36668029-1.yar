rule Virus_Autorun_Trojan_GenericKD_36668029_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKD.36668029_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3440d4a0cbd19faf84598e6b323f57179c7b1409077c9b7ae1c01af087d901fc"

  strings:
    $s1 = "Clock Microsoft " fullword wide
    $s2 = "Clock " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}