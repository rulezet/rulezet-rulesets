rule Virus_Hijack_Backdoor_Hangup_B_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f62bd26e524a7b0c869aae3153d5c93de0c0015291ba822881d2e0cbdf17017"

  strings:
    $s1 = "Macromedia Flash movie (*.swf)|FutureSplash movie (*.spl)" fullword wide
    $s2 = "Macromedia Flash Player" fullword wide
    $s3 = "Shockwave Flash 6.0  r65" fullword wide
    $s4 = "Macromedia Flash Player 6.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}