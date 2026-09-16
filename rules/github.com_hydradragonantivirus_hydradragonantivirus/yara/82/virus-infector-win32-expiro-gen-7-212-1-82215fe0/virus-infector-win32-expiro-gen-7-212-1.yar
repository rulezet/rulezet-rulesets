rule Virus_Infector_Win32_Expiro_Gen_7_212_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0a9278dbe3fdb502c50c90301537a9391009fe9362656ee82869a8d84598b4b"

  strings:
    $s1 = "m guna" fullword ascii
    $s2 = "y<SWam>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}