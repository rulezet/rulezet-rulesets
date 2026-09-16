rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_521 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_521.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "715eabbc66d8baeedb2f98b5897ff58ddcf54f0242ddb512995299d289b5f8b0"

  strings:
    $s1 = "RLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}