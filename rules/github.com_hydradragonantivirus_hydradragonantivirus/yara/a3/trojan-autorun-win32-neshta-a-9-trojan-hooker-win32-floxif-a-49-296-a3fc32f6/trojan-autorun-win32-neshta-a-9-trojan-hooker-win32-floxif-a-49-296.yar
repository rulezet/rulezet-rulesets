rule _Trojan_Autorun_Win32_Neshta_A_9_Trojan_Hooker_Win32_Floxif_A_49_296 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Win32.Neshta.A_9.vir, Trojan.Hooker_Win32.Floxif.A_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e45914ee0959583a42d2caa885d53b355cee3c0856eefa8720745c109606aa4"
    hash2       = "43ec7d19c6912d5f6cd8b53f4881b73f8fb48d3fcbddee00014bced572e1b272"

  strings:
    $s1 = "Image for Windows - Complete System Backup Solution" fullword wide
    $s2 = "Image for Windows" fullword wide
    $s3 = "Image for Windows Drive Image Backup Utility" fullword wide
    $s4 = "TeraByte Unlimited" fullword wide
    $s5 = " 2002-2023 TeraByte, Inc.  All Rights Reserved." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}