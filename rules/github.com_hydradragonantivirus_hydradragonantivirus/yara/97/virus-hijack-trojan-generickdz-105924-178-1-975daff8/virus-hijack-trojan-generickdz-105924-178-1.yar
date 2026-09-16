rule Virus_Hijack_Trojan_GenericKDZ_105924_178_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93d9852640a45e7d4d0bc436aac3af1df166f298bd1d9f84dbb6f60c4fc3f77c"

  strings:
    $s1 = "Adjust screen brightness" fullword wide
    $s2 = "Slide showHSpecify when you want " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}