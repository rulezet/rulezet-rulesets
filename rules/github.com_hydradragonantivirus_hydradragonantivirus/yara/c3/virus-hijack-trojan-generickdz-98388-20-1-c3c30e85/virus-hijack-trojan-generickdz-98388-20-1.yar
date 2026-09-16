rule Virus_Hijack_Trojan_GenericKDZ_98388_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "621d17cd7b4b0e496d989cca6cbf52f2a37eaa5a49878e285dacc0bd45aa5b1d"

  strings:
    $s1 = "tAsh!&X" fullword ascii
    $s2 = "moUL[5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}