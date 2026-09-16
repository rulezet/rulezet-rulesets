rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_a4IIY9p_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@a4IIY9p_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4454619459fe60b2efefa6e6fd4c87f0f7700e0fcbdfe9b443073852d9522c6f"

  strings:
    $s1 = "&XSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "&XSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s3 = "jILT(!-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}