rule Virus_Infector_Win32_Expiro_Gen_7_184 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_184.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b12cc92a4d94a5099be2f5195bab36e54e5f19508ca35147c684353fda7f791e"

  strings:
    $s1 = "dARE#p" fullword ascii
    $s2 = "\"MuZZ%Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}