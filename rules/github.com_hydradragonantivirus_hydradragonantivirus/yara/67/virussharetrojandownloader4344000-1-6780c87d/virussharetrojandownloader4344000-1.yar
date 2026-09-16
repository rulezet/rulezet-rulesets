rule VirusShareTrojanDownLoader4344000_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344000_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49128faca2b1f87667f544dfdb882011cd21e03c755059b1497c06f004474bcd"

  strings:
    $s1 = "kingsoft antivirus mail monitor proxy" fullword ascii
    $s2 = " goto loop" fullword ascii
    $s3 = "tions Copyright (c) R" fullword ascii
    $s4 = "Mail From:<" fullword ascii
    $s5 = "Subject: =?gb2312?B?" fullword ascii
    $s6 = "Apar';/" fullword ascii
    $s7 = "  Socket" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}