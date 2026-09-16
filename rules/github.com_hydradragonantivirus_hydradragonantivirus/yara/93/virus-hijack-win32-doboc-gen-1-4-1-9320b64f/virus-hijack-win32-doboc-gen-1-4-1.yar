rule Virus_Hijack_Win32_Doboc_Gen_1_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40a15009c4f90417d1bda9fa811bc45d70f99c0ae0bc73d6f3f60db40dab9d46"

  strings:
    $s1 = "frog?6q" fullword ascii
    $s2 = "MILA@R" fullword ascii
    $s3 = "rgz@till" fullword ascii
    $s4 = "hATE`-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}