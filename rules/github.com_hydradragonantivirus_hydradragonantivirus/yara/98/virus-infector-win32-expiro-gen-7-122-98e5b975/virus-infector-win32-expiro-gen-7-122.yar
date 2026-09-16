rule Virus_Infector_Win32_Expiro_Gen_7_122 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_122.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "584b827b6db18f7dbc006c7be2a296b891dfda42a18a6154788022df156eb734"

  strings:
    $s1 = "q|T5i&oPAl" fullword ascii
    $s2 = ":TOle." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}