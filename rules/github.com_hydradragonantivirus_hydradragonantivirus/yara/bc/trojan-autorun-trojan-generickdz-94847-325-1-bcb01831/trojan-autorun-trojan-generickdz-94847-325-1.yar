rule Trojan_Autorun_Trojan_GenericKDZ_94847_325_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_325_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5026e1104a0f444b014faefcaed38034e54e12356f3f47c8620cd1d3f354f39f"

  strings:
    $s1 = "tProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}