rule Virus_Hijack_Trojan_GenericKDZ_98388_87_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf0a608050fe0ed7de80716982d5668e4e1efc412f4ded0430281872cb209602"

  strings:
    $s1 = "$#Tilt " fullword ascii
    $s2 = "C=?FlAx" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}