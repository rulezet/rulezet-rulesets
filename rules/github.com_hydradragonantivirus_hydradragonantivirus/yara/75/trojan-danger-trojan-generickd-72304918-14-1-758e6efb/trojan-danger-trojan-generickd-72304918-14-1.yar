rule Trojan_Danger_Trojan_GenericKD_72304918_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8a9f5c0fd5713d33430f2ce2a4a492f7e1eb204388196f8f8c6507b3a5f69db"

  strings:
    $s1 = "aWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}