rule Trojan_Danger_Trojan_GenericKD_67166905_448_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_448_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd4de39609753073eca0a6e9d1308a17e8348e0cd7e2b2d0e4313aa2a7501607"

  strings:
    $s1 = "+&What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}