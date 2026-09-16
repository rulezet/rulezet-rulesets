rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_a4IIY9p_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@a4IIY9p_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d54de01499c3969f0f7355468ba4d2e683fa78c164cfe762985612bdcbd0786"

  strings:
    $s1 = "e/l,6y connected'r" fullword ascii
    $s2 = "b;address not availabl" fullword ascii
    $s3 = "F; empty" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}