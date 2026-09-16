rule Virus_Infector__Win32_Expiro_Gen_7 {
  meta:
    description = "datamaliciousorder - file Virus.Infector _Win32.Expiro.Gen.7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cd549f846b9c96599a7984d3917553c10251727046a69798d3f6b0bd3369351"

  strings:
    $s1 = "]sOle:^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}