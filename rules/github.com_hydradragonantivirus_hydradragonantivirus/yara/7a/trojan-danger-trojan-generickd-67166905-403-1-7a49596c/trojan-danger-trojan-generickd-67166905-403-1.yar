rule Trojan_Danger_Trojan_GenericKD_67166905_403_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_403_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a379c79fb7b67464cb7c81ae9d6a8f88eaf1926adc41d150e7f6a30de83717d"

  strings:
    $s1 = "IWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}