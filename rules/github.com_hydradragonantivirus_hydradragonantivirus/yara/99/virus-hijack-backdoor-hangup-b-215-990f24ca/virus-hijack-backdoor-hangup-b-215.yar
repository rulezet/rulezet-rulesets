rule Virus_Hijack_Backdoor_Hangup_B_215 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_215.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57e46fbd7725a63de165fe5a619c91a6060c246995dc42be3d8503514ca50628"

  strings:
    $s1 = "_2your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}