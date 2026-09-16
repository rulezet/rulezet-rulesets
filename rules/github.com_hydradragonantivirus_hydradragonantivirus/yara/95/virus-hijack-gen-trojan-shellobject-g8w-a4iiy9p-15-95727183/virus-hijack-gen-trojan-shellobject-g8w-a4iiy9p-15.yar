rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d38f4ad12424c597f4673471d1f959d4f56fcc5d4631461b990b0916e741eeb"

  strings:
    $s1 = "JSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}