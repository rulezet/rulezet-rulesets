rule Virus_Hijack_Trojan_GenericKDZ_103285_879 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_879.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147684860d375a19dcb0eb6da419e7edf3329a43601b9edd2c51bf4c054224ac"

  strings:
    $s1 = "2Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}