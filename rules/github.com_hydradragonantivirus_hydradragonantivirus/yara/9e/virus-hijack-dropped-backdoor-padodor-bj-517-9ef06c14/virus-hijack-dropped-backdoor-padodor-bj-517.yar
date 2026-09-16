rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_517 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_517.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7672884c9e7dd9719ed65b16b3601cb0e530c3efc5e5a7e14c2b7aaa2e7efacd"

  strings:
    $s1 = "zLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}