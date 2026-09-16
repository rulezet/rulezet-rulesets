rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aOGzovi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5d6099662a82872107827924dd2aff7ea96dac81c6cdb7f99e74f90fc56435"

  strings:
    $s1 = "JSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii
    $s2 = "$maSK##" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}