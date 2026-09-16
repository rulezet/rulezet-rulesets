rule Trojan_Danger_Trojan_Generic_4385790_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.4385790_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df5020916aad12a49435bb58e8fac31341dcf0f6137ee55a38a6aab715d08cde"

  strings:
    $s1 = "Zvvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}