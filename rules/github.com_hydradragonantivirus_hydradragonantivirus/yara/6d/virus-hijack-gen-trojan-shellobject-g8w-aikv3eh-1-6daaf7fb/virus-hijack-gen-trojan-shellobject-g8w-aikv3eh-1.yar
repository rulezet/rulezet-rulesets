rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49341891adca6dc47735de5a5577d428a2832a5238e262d113f97c3c0e620fa9"

  strings:
    $s1 = "epSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "epSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}