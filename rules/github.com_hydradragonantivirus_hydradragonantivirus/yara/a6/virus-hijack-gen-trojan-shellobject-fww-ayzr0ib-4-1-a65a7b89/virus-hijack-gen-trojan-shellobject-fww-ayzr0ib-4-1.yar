rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e92f1cb1627323b7abe454a60777ce7d8dd6cf40ecae99c9aaf52a273e58d4d"

  strings:
    $s1 = "Unable to notify ARM Service - Service may be disabled or not installed: " fullword wide
    $s2 = "Error Code: %1!d!" fullword wide
    $s3 = "AppTakeOwnershipForFileTypes failed, will display AdvancedAssociationUI" fullword wide
    $s4 = "Copyright 2013 Adobe Systems Incorporated" fullword wide
    $s5 = "Source file not signed by Adobe: " fullword wide
    $s6 = "Preferences set successfully" fullword wide
    $s7 = "Start Service..." fullword wide
    $s8 = "Stop Service..." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}