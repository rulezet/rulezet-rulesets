rule Trojan_Autorun_Trojan_GenericKD_72517131_211_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_211_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4626d47d1a8c10c409fae731505614d28a6d59b32545c23c9a79a07b962cb7f"

  strings:
    $s1 = "this notice will include a copy of your agreemen" fullword ascii
    $s2 = "physical computer, is considered a separate computer for purposes of this agreement. This`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}