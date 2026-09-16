rule Virus_Infector_Win32_Expiro_Gen_7_47 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0404dc809085eae907c45f092b9285362013d75a8b4d713a33bb760b2d9d89ba"

  strings:
    $s1 = "LEAM}<_" fullword ascii
    $s2 = "VERd?>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}