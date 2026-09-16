rule Virus_Sysbot_Dump_Generic_Dialer_5485D7ED_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.5485D7ED_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63e7e4153649c845ca4af478f544b69b42e6f6afb8f7f6bb497570ba943e3f8e"

  strings:
    $s1 = "Qe;SpOoL:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}