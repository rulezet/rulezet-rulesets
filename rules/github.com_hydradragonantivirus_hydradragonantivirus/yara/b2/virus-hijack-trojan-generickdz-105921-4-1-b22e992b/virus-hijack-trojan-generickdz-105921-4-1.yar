rule Virus_Hijack_Trojan_GenericKDZ_105921_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8796ff491fc17373ba18aef75a48945831e9e0ca7f33389d6b4754ea13171f71"

  strings:
    $s1 = "*,v[CUIr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}