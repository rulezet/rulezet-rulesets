rule Virus_Hijack_Gen_Trojan_ShellObject_x8Z_a4IIY9p {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8Z@a4IIY9p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c5329a9ba2a886efe90bd96707a08f83703b2e36c43a5e921b3c9cfa488b71"

  strings:
    $s1 = "j9Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "j9Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}