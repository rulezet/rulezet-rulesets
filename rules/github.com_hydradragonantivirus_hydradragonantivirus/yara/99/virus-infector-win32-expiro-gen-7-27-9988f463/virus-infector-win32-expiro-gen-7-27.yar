rule Virus_Infector_Win32_Expiro_Gen_7_27 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1800d94bdf65fee5ab6cd712261532aba20c4819c1dcc800f89cbf57da0465"

  strings:
    $s1 = "($hakU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}