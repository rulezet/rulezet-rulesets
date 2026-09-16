rule Virus_Autorun_Trojan_GenericKD_66277505 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKD.66277505.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426dbf93eb989c98aeada781057853b6165c8752abbca08468f03bf0e9e3ef6b"

  strings:
    $s1 = "OMFG Studio?Operating System" fullword wide
    $s2 = "About Clock" fullword wide
    $s3 = "OMFG Studio" fullword wide
    $s4 = "OMFG All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}