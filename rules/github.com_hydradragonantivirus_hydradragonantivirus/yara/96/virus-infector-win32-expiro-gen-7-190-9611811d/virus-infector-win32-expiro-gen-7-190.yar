rule Virus_Infector_Win32_Expiro_Gen_7_190 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_190.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d7d73e8b73f61399f27578c1fb36d38a97a9c23d7dc741c920d4fbd8787f9d5"

  strings:
    $s1 = "bENA!\"" fullword ascii
    $s2 = "MULE]gF" fullword ascii
    $s3 = "swAG$J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}