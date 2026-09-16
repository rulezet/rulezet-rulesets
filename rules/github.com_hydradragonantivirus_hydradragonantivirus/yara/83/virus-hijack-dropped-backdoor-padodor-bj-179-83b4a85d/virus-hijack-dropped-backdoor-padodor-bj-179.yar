rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_179 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_179.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33a7c7f1a3131377693ee4b21f4724f41bed2ea8f323270fd17857f45c4979a2"

  strings:
    $s1 = "}`active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}