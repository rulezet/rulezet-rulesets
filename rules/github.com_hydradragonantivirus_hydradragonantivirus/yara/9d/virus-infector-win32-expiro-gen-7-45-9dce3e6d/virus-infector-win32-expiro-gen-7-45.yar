rule Virus_Infector_Win32_Expiro_Gen_7_45 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "938182a960b4bdbefdc46fc96d477f7b5f6806c52e718c2cc3306b5b7e4e8b1a"

  strings:
    $s1 = "LEAM}<_" fullword ascii
    $s2 = "VERd?>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}