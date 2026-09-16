rule Trojan_Danger_Generic_Dacic_1A7FA519_A_39934DE4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.39934DE4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57e792f61f7e531490c8e7b5a1a00be0757381777af0912a7184e01f60fe52ef"

  strings:
    $s1 = "%mSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "%mSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}