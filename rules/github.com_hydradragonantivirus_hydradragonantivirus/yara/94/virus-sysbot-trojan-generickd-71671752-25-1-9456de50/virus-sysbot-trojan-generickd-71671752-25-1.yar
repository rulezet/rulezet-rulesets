rule Virus_Sysbot_Trojan_GenericKD_71671752_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0adfd4825f34f4a9da2092f907ef4e4caa7a8bbf3c8bc272d5dc63f9dda5380"

  strings:
    $s1  = "costrel" fullword ascii
    $s2  = "ponderosity" fullword ascii
    $s3  = "outthieve" fullword ascii
    $s4  = "POSTCANONICAL" fullword ascii
    $s5  = "INFINITATION" fullword ascii
    $s6  = "AGUISHLY" fullword ascii
    $s7  = "OPPUGNANCE" fullword ascii
    $s8  = "ANIMALIC" fullword ascii
    $s9  = "PERJURE" fullword ascii
    $s10 = "ALIPTES" fullword ascii
    $s11 = "Gastromyces" fullword ascii
    $s12 = "Glutathione" fullword ascii
    $s13 = "Iminazole" fullword ascii
    $s14 = "Overrational" fullword ascii
    $s15 = "Solvolysis" fullword ascii
    $s16 = "konjak" fullword ascii
    $s17 = "Ribbed" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}