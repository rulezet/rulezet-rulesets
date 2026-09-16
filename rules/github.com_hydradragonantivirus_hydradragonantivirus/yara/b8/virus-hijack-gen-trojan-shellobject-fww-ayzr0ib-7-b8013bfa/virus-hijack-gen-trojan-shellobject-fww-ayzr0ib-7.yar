rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3417eb51561705af441e888ebc7c88263c052acff76e686cc245a72d27fa39f6"

  strings:
    $s1 = "t?purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}