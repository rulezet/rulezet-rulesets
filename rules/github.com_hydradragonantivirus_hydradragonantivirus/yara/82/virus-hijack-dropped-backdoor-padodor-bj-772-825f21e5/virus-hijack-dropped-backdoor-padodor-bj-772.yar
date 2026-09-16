rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_772 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_772.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5eba618ca7bf00a3e55ba999fa0b4b15774907a7e1382be200ac69a97961147"

  strings:
    $s1 = "%are a part of the software and may not be used s" fullword ascii
    $s2 = "I]COZE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}