rule Trojan_Autorun_Win32_Virlock_Gen_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "717f4b0f22abe00b12e1848ef13b8d7d1d78d1a61e56c971acc084556909c790"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}