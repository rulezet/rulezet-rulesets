rule Virus_Infector_Win32_Expiro_Gen_7_204 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_204.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d4a2b5f8f2ab57a8bc9bfd1c5c9dc2f85992496db4c5f560a51614c3e528aa"

  strings:
    $s1 = "BawD}`m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}