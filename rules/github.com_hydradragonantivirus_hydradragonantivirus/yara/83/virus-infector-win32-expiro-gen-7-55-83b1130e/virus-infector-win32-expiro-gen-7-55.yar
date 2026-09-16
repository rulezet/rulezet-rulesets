rule Virus_Infector_Win32_Expiro_Gen_7_55 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bacebe9e353309dc6a03106f312d53bb63bc1dcde939c25c485b17cf6e91ea6"

  strings:
    $s1 = "x}bEND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}