rule Virus_Infector_Win32_Expiro_Gen_7_18 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "111729df092abe5d7f388450da3176545f0e7c52f22cc9bac9d2c0267ab1399a"

  strings:
    $s1 = "sHor{fB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}