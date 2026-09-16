rule Virus_Infector_Win32_Expiro_Gen_7_174 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_174.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a879295a46188cae5dff9546184d70fca89e55ae25c81450f37309275d82b433"

  strings:
    $s1 = "DEAf]A`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}