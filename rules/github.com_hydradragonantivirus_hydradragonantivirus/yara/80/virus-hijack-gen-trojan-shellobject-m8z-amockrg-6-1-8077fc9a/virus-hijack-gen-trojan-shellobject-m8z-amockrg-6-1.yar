rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58bc9e4899e959eefe6c29ac2504091b3f3bec3b9928976193788297b7d86686"

  strings:
    $s1 = "PropertySheetWithLogo Version 1.0" fullword wide
    $s2 = "About PropertySheetWithLogo" fullword wide
    $s3 = "PropertySheetWithLogo MFC Application" fullword wide
    $s4 = "PropertySheetWithLogo Application" fullword wide
    $s5 = "Night Vision" fullword ascii
    $s6 = "&About PropertySheetWithLogo..." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}