rule Trojan_Danger_Trojan_GenericKD_72304918_220_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "accdabb6d81e10cb13f927ba84ccf639dd1287ea5089607a8ee7d4067f3b4f2c"

  strings:
    $s1 = "eSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}