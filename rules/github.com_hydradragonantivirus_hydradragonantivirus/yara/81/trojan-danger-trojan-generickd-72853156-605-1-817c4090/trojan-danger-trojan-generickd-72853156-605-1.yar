rule Trojan_Danger_Trojan_GenericKD_72853156_605_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_605_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "240c6b519ed1d5a19763a11fe7bca4e8ec0379758c24978909b0871ec19e2c9d"

  strings:
    $s1 = "OMFG Studio?Operating System" fullword wide
    $s2 = "About Clock" fullword wide
    $s3 = "OMFG Studio" fullword wide
    $s4 = "OMFG All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}