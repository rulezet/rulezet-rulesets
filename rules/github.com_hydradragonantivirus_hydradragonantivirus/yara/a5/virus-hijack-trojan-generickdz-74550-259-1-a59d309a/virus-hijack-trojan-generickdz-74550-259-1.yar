rule Virus_Hijack_Trojan_GenericKDZ_74550_259_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_259_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fb45e49996fb0f5ab5e9a61630ebb4db99f84885ea0f4fc6f5e14d186d73e77"

  strings:
    $s1 = "MEse{F&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}