rule Virus_Infector_Win32_Expiro_Gen_7_7 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23ad64bfa8e2f93ec4fc0f1c049f1cd154a5471db8bd7dd763efde070e1d3c1f"

  strings:
    $s1 = "YKT.[mEwl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}