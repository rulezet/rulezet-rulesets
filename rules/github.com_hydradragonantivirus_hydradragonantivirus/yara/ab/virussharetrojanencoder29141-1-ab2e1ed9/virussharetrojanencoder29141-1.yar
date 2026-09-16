rule VirusShareTrojanEncoder29141_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanEncoder29141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a880f0ca754e20935bc00965ae4d34aaaac788cd399710bddd40ade4051a1461"

  strings:
    $s1  = "Wheesht" fullword ascii
    $s2  = "Chaitya" fullword wide
    $s3  = "Permissory" fullword ascii
    $s4  = "Unscissored" fullword ascii
    $s5  = "Ribandlike" fullword ascii
    $s6  = "Proximation" fullword ascii
    $s7  = "Tensibly" fullword ascii
    $s8  = "Zopilote" fullword ascii
    $s9  = "SUSU]gEU" fullword ascii
    $s10 = "Uniate" fullword ascii
    $s11 = "Acetyl" fullword wide
    $s12 = "Soporifical" fullword ascii
    $s13 = "saki<!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}