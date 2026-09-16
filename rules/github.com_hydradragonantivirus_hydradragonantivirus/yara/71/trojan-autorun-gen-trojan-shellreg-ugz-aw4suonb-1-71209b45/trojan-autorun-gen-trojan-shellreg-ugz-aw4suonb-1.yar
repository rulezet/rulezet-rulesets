rule Trojan_Autorun_Gen_Trojan_ShellReg_UGZ_aW4SuOnb_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.ShellReg.UGZ@aW4SuOnb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db7a96725d301e12e2cc5d692c00db6f60ad11c718b443f0d3f095ff0aefbc4f"

  strings:
    $s1 = "whundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}