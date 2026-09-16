rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0f9236141237670aabee1b4f0c641300bb6f206eafcb9fe8c244dd1294e52b9"

  strings:
    $s1 = "!Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}