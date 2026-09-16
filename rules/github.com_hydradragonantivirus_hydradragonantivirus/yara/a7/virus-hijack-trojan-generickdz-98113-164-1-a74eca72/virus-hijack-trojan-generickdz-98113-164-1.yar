rule Virus_Hijack_Trojan_GenericKDZ_98113_164_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_164_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2d5c92cb2154bddb5f1c60fbda301728fc1194fb3ea6d60427fb6b8faf22eab"

  strings:
    $s1 = "-`mEiO " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}