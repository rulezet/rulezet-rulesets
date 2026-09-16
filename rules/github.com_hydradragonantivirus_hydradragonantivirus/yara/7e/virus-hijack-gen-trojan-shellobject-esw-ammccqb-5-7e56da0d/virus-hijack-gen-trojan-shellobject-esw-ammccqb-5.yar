rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bad99879452b2f6eb5899f58d4262b535a520a3f72baf7670bd2f01c941c6de8"

  strings:
    $s1 = "whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}