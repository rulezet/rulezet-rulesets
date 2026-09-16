rule Virus_Hijack_Trojan_GenericKD_66277505_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKD.66277505_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15ad47ed230951034706f109ab1b9e1438369183eca4a568236b4ecd3d58b8fe"

  strings:
    $s1 = "OMFG Studio?Operating System" fullword wide
    $s2 = "About Clock" fullword wide
    $s3 = "OMFG Studio" fullword wide
    $s4 = "OMFG All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}