rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2c406da90cf9b88675f4e22abe23ad0ae46b3b88fcfae9ddac23fc646a488f"

  strings:
    $s1 = "TSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}