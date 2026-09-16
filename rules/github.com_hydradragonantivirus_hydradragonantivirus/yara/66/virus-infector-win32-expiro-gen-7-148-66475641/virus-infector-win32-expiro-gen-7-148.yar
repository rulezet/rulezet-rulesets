rule Virus_Infector_Win32_Expiro_Gen_7_148 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_148.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93396e3e30351df0cfdde7ec83b590fdc956f0116f48a70f25f5610b4050fca"

  strings:
    $s1 = "n#welK" fullword ascii
    $s2 = "':deRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}