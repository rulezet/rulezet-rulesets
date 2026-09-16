rule Trojan_Danger_Generic_Dacic_1A7FA519_A_6C3260E3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.6C3260E3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a19aa66381f1d6a90e6697e8e0cf30c1d1f737364b625e3ea355f85ab7492a3"

  strings:
    $s1 = "cSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}