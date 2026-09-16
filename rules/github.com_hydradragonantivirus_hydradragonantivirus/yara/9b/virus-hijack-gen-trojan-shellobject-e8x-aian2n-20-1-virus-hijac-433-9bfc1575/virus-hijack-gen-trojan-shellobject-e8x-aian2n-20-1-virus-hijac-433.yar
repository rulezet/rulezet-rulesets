import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_20_1_Virus_Hijac_433 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_20_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d05f40601d41dc2f50f647b15562e8750cac4fde72a5e60d7b0a43b5547a076c"
    hash2       = "6496f5ecac28a4a31adaa379b396a1548ffa301176524194ba38193764450936"

  strings:
    $s1 = "Error : 0x{0:X8}" fullword wide
    $s2 = "Failed to create symbol handler for path '{0}'. Error : 0x{1:X8}" fullword wide
    $s3 = "Failed to cleanup a symbol handler. Error: {0}" fullword wide
    $s4 = "Device inserted, searching for drive with label '" fullword wide
    $s5 = "No device found with label '" fullword wide
    $s6 = "Changing label of drive " fullword wide
    $s7 = "Copying files to drive " fullword wide
    $s8 = "Starting new devices listener..." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}