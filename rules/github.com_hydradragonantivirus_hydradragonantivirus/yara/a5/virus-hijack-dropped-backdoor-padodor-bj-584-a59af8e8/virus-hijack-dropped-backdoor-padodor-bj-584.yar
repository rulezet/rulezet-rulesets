rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_584 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_584.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44c5b327f590b760c953045dae6037350340130660b9085332c4fc33f898704c"

  strings:
    $s1 = "Microsoft products. You agree that w`" fullword ascii
    $s2 = "@Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}