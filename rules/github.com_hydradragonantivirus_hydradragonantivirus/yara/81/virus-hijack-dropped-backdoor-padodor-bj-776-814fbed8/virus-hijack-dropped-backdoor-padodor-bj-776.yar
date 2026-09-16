rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_776 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_776.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada23eaab49f445200a47f8bb12074aa1cdf6d975713e3cdb5f3c85bdb4e8016"

  strings:
    $s1 = "lbMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}