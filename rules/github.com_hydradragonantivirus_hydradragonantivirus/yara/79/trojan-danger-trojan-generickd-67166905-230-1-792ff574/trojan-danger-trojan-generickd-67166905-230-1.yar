rule Trojan_Danger_Trojan_GenericKD_67166905_230_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_230_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5493e4d03043d1661641acdf74f915809c87029e0090141f585f04074329366d"

  strings:
    $s1 = "0purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii
    $s2 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}