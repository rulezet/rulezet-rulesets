rule Virus_Hijack_Win32_Doboc_Gen_1_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d82f3cd684985b5a7c11686926268176397d3275362773e31c90ac7bc45b74"

  strings:
    $s1 = "bOnk@14" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}