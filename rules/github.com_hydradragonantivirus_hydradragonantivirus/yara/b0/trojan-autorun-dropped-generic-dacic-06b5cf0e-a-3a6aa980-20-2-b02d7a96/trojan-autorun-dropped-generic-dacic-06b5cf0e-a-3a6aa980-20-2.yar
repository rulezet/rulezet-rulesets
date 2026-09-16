rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_20_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31db3643ba34d5a1f7b7f5aebdc877afb42c37ff421909f965c9d5beaeed50bd"

  strings:
    $s1 = "D:\\workspace\\sourceCode\\virtual studio project\\console\\runDllFromMemory\\Release\\setup.pdb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}