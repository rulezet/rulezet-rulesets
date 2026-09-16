rule Virus_Infector_Win32_Expiro_Gen_7_130 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_130.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38c37eca19858b38a611883572a67e08568db33fc7c3fa5ea1a0b14c00c3ed8"

  strings:
    $s1 = "bENA!\"" fullword ascii
    $s2 = "MULE]gF" fullword ascii
    $s3 = "swAG$J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}