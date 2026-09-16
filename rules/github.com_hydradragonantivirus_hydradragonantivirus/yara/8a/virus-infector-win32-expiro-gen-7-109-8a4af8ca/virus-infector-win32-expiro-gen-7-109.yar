rule Virus_Infector_Win32_Expiro_Gen_7_109 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_109.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "286d3f2076d5d322eae4d6df0a2b1c79964cf6d0a96c851eab67bdbd6a9583a7"

  strings:
    $s1 = "aRsE?xP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}