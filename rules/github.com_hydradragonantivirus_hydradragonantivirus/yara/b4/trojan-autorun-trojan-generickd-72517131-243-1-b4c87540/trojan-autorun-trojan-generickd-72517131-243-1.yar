rule Trojan_Autorun_Trojan_GenericKD_72517131_243_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db9102a14a4d876b22b1ee0ce2400eac2165612a6e6035021151862c75ad51a2"

  strings:
    $s1 = "5;fUll,^w:pE5}lT" fullword ascii
    $s2 = "{scYt:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}