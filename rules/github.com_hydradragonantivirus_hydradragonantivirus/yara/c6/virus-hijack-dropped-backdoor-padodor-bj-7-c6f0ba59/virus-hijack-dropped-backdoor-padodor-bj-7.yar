rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba08e75a923cc54005b0378d14eb24746115ae3203f8b99504e21d9e27a6384c"

  strings:
    $s1 = "&active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}