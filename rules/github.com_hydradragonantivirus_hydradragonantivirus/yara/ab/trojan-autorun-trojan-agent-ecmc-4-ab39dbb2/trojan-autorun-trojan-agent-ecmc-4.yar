rule Trojan_Autorun_Trojan_Agent_ECMC_4 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.ECMC_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a985661b5dbc92c29ef82081551fd8c60bebf07afc5d60a9b57061aebf9dd5f1"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}