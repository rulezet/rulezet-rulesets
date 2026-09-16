rule Virus_Hooker_Trojan_VB_Agent_AWT {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.VB.Agent.AWT.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5646f469c13db66bdf89d64ab96e87203336e8dbf188cb91c09471b42aefaa6"

  strings:
    $s1  = "Geologer" fullword ascii
    $s2  = "bystreet" fullword ascii
    $s3  = "misunderstandingly" fullword ascii
    $s4  = "animality" fullword ascii
    $s5  = "Crummie" fullword ascii
    $s6  = "Accelerative" fullword ascii
    $s7  = "Concededly" fullword ascii
    $s8  = "Abreaction" fullword ascii
    $s9  = "Basifier" fullword ascii
    $s10 = "valuable rings trient guisait bou" fullword wide
    $s11 = "claque'e broussai" fullword ascii
    $s12 = "Flinty" fullword ascii
    $s13 = "Incantation" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}