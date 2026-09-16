rule Virus_Infector_Win32_Expiro_Gen_7_57 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e20847e64bd0c74c9bfa94c927b0f491ccdc4e0d8ccdd993504fbaa23647dba1"

  strings:
    $s1 = "Bite?jm" fullword ascii
    $s2 = "FriB;n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}