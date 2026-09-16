rule Trojan_Autorun_Trojan_GenericKD_72517131_135_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_135_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c8c13632d4471066eefd25652b08388ee488bc6d039f421d67173679c88e54f"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii
    $s2 = "hEEl]I^g[`XmYA7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}