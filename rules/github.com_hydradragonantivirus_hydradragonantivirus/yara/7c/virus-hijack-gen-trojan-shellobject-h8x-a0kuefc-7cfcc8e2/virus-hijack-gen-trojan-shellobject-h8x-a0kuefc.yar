rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a0kuefc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6af14882d0d65dede523bffb2c66e155d8e29525e78f37405729df45786611"

  strings:
    $s1 = "$|virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}