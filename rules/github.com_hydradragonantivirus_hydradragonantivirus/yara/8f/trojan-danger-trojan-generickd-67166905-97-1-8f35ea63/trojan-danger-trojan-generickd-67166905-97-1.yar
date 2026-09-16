rule Trojan_Danger_Trojan_GenericKD_67166905_97_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_97_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1b0537980f2b6e33110c5c008eadd14ea71a190e5452a425ff55873cdf9152f"

  strings:
    $s1 = " What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}