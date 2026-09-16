rule Trojan_Danger_Trojan_GenericKD_67166905_444_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_444_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c9bfa590abb02e30c8d1a63bebb672010c23528a57189979a5c9e6c265b646"

  strings:
    $s1 = "AWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}