rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_778_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_778_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8daaaf3ac3f532329fe4f21ffdcc8084941a75b285e212ec2e1061b4dc5da2d7"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}