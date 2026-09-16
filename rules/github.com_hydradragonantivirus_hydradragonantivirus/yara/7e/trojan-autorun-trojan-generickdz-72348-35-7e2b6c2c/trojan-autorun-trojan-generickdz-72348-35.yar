rule Trojan_Autorun_Trojan_GenericKDZ_72348_35 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c7862e3471c50a90d74c692f0dcd3517edba9d49efa26b8f0ff6991eebfbcc4"

  strings:
    $s1 = " edition software may not be used for commercial, non-profit, o" fullword ascii
    $s2 = "xes and expenses. You agree that you have not relied on" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}