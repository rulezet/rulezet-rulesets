rule Trojan_Danger_Trojan_GenericKD_67166905_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "686e8524a051081bf00f92caad9aa70651bae97bbb60208fe630b43b9782ea03"

  strings:
    $s1 = "NidE{s%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}