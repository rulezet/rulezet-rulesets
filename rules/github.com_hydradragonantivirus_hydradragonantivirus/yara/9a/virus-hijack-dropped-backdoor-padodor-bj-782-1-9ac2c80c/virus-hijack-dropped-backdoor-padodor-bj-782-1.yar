rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_782_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_782_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "127f1c742543a721131550fd20aa763dd0ab99e57b8e8d4f244e1149d345f226"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}