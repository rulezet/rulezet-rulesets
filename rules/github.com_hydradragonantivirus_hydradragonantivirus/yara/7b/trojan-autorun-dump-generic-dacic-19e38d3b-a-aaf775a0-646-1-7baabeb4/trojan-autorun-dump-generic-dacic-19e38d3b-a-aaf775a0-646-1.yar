rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_646_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_646_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960c2aabe70ac0ee8c472f9b50627533557713aabd4bef3c2d0067c98c55fac8"

  strings:
    $s1 = "${are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}