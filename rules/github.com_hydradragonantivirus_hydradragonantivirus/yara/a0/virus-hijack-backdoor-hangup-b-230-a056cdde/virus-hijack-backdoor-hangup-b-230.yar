rule Virus_Hijack_Backdoor_Hangup_B_230 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_230.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e8a5b7952286e36cafad2974386444453a514132763d87ab73da6247ee611e"

  strings:
    $s1 = "yTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii
    $s2 = "0>RIne" fullword ascii
    $s3 = "%>RIne" fullword ascii
    $s4 = "4>RIne" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}