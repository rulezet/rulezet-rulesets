rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_186 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_186.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b51677b53cf919859951a67343d555f980c7dac78792dca955bc5cde19000f9a"

  strings:
    $s1 = "~vZCF?EmYd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}