rule Virus_Sysbot_Trojan_GenericKD_71671752_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea5da7ee6b31d3a5a4e4f9272fe93d15672a1752592aca30f91e43fb131fd5ab"

  strings:
    $s1 = "RedO:Y" fullword ascii
    $s2 = "'3,iNCh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}