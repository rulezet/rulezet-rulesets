rule Virus_Hijack_Trojan_GenericKDZ_103285_273 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_273.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f470542555458951808c502d2f9bd10dea5c602180d5d5c653a1f59d2fb22e2"

  strings:
    $s1 = "ESubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}