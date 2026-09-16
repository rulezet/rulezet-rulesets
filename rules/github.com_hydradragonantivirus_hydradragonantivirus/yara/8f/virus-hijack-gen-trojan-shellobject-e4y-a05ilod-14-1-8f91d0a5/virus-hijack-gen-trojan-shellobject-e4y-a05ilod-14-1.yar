rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3c7e1ad10aff7ebe3058ba08ad2c23a41853bcdaf6eb0b2e1a7d91ca84811f"

  strings:
    $s1  = "Accommodatingly" fullword ascii
    $s2  = "muggins" fullword ascii
    $s3  = "charlatanic" fullword ascii
    $s4  = "Diviner" fullword ascii
    $s5  = "Agelessness" fullword ascii
    $s6  = "Amortize" fullword ascii
    $s7  = "Censorship" fullword ascii
    $s8  = "appari urna" fullword wide
    $s9  = "tetra banche" fullword wide
    $s10 = "Lr purga tigne" fullword wide
    $s11 = "Illudi giuri rupi anima" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}