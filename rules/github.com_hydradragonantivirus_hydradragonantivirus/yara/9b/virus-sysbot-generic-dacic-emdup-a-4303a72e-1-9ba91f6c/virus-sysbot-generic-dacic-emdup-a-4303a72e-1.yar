rule Virus_Sysbot_Generic_Dacic_Emdup_A_4303A72E_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Dacic.Emdup.A.4303A72E_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7cc6380a3a9cda8f41777a7c984b4c63e0a41ea1e5a673dfe939dfa238f1bb2"

  strings:
    $s1 = "CapH!t-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}