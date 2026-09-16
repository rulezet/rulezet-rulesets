rule Virus_Infector_Win32_Expiro_Gen_7_147 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_147.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c32eec9ce74168adabc3434b33a61bafc84921b818d9f8e72c173047af4ddf"

  strings:
    $s1 = "TeAM[=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}