rule Trojan_Danger_Trojan_GenericKD_72304918_111_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68cfbc0db7b94f68d2d7ddd07cb55fe018c3d235a9a57a847bf187bd033cc2cb"

  strings:
    $s1 = "eWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}