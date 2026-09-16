rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_775_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_775_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d18d399802274a7f64990c431831b6c596135803ac56753220f737c176cce48"

  strings:
    $s1 = "mendable" fullword wide
    $s2 = "Subabdominal" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}