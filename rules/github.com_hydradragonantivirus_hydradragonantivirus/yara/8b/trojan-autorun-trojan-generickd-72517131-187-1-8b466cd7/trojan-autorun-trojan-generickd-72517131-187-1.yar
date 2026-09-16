rule Trojan_Autorun_Trojan_GenericKD_72517131_187_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c3b230e4bbffb34be41b9be5232793a6dc479876fe6b2b6fcd1331de339961"

  strings:
    $s1 = "athis notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}