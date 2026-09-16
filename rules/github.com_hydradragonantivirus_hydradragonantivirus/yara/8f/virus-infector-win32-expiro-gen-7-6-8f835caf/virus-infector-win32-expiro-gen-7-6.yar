rule Virus_Infector_Win32_Expiro_Gen_7_6 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fda85ee88daf302027940d026c4ba7e40eed61d080826b8a15417a36c50ab51"

  strings:
    $s1 = "-&hiGh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}