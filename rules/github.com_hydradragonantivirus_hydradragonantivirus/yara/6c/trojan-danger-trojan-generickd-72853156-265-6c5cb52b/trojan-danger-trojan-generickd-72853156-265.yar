rule Trojan_Danger_Trojan_GenericKD_72853156_265 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_265.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f5219ef49f795009dffbdaa5420528f8a54a8da3222d44c2c7de90878c0fdf0"

  strings:
    $s1 = "RoRY}tkihkedYR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}