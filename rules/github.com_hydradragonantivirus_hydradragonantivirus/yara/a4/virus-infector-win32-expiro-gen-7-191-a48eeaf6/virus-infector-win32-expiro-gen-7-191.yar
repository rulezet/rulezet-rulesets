rule Virus_Infector_Win32_Expiro_Gen_7_191 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_191.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6dedc0bd13255166315e8fe9a8568403eee62d85967fe99d92f18cb061e8dd2e"

  strings:
    $s1 = "crUm!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}