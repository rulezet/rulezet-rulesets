rule Virus_Hijack_Trojan_GenericKDZ_79663_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad519586571306b4229b5b6375cfc5a5e058c2513eac5cc9eeb7b900ec32288a"

  strings:
    $s1 = "E)oner`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}