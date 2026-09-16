rule Trojan_Danger_Trojan_Generic_36486627_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14344450ea2af97ddfad88d4d2dea7f636fb54aba301cf664978536d24316d9d"

  strings:
    $s1 = "KApurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}