rule Virus_Infector_Win32_Expiro_Gen_7_179 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_179.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "234637410f3614a80f02bb0cabad3f3e1079d8356001323df84f1e4fd1f8a3e7"

  strings:
    $s1 = "ALOp>v8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}