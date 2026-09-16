rule Virus_Infector_Win32_Expiro_Gen_7_115 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_115.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e91afe8311451029e8e23f48ca77fa10910a3217155b20eff0044ef9242f8ca3"

  strings:
    $s1 = "miCO>@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}