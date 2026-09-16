rule Trojan_Danger_Trojan_GenericKD_67166905_226_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_226_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e473c8ddde588382fcd51b6bd9ca92b88e29c8093700438c6b082ec9582f7e46"

  strings:
    $s1 = "UMWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}