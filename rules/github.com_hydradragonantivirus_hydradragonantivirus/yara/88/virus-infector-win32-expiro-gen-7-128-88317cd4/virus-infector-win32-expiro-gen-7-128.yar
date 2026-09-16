rule Virus_Infector_Win32_Expiro_Gen_7_128 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_128.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f9971983caf4ca9f633828acaeb061d8a0e20278b8980e77ab0fe3717f9fc8f"

  strings:
    $s1 = "]sOle:^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}