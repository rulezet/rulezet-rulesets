rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c5d3518602c1dea1b1795d2a8e4c31658c742f1a5cad91c34fe1ed50a8a9a49"

  strings:
    $s1 = "q|T5i&oPAl" fullword ascii
    $s2 = ":TOle." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}