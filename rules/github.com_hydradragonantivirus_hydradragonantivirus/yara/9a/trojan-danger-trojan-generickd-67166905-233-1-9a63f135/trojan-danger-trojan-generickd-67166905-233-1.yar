rule Trojan_Danger_Trojan_GenericKD_67166905_233_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0159cc1f8d1d38fd1b08ce2423ab099bd77a6314bcb2b0b030c764e7b1a04c8"

  strings:
    $s1 = ";What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}