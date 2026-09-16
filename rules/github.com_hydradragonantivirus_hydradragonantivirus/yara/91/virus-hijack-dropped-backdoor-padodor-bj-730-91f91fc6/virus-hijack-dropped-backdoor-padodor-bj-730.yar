rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_730 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_730.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54132627c99021bc70f7810b317d6fe20b4e0b809d6688a6ec65923463a98438"

  strings:
    $s1 = ")are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}