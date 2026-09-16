rule Virus_Infector_Win32_Expiro_Gen_7_155 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_155.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c77ffe9f4ceea16fbfcf0276e07110ede23d4f625e9c5f48b9f1a633bff14e50"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}