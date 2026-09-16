rule Virus_Hijack_Gen_Trojan_ShellObject_x8Z_a4IIY9p_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8Z@a4IIY9p_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82e00494ba466565d33ea5931821cf5b50d87f5a93b91268afe326974fc5f5b4"

  strings:
    $s1 = "2Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}