rule Virus_Infector_Win32_Expiro_Gen_7_4 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80b155699ca8770a69aa4beda421c8c61d37e246a7441c49fff40a864f6ef0cf"

  strings:
    $s1 = "($hakU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}