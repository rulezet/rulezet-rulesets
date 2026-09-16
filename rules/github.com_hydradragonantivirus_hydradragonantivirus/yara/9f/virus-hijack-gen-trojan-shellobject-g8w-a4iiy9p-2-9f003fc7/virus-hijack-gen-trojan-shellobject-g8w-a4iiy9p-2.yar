rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "380a5c65a97454bcb345817add0be1b1eb866056df95c87448d60594a6757945"

  strings:
    $s1 = "~Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii
    $s2 = "v dUeR&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}