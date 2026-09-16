rule Trojan_Danger_Trojan_GenericKD_67166905_96_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_96_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b5ec20c9c3d60bd06c636a1d76fac2a656a2c1d74f56f791f63cf327b8ea336"

  strings:
    $s1 = "aSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}