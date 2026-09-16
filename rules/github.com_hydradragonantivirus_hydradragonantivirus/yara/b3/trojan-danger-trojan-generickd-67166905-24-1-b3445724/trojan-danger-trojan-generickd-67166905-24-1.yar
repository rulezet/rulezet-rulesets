rule Trojan_Danger_Trojan_GenericKD_67166905_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d66d5a194673640ae9a8909fe91a60ee4f1c0066e44b248c66d486987b98b2d"

  strings:
    $s1 = "Uvirtualization, see the Additional Terms." fullword ascii
    $s2 = ";sICK:T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}