rule Trojan_Danger_Generic_Dacic_1A7FA519_A_351C6BEF_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.351C6BEF_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69a32951e8b05915f3e06052e0ccb89c4cc3fca6ff289c2e902c0631776254af"

  strings:
    $s1 = "Y)Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "Y)Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}