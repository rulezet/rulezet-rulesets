rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65601487f4efc609f54f7c22b1562759b26360121a321e20479d17ce1c8f4634"

  strings:
    $s1 = "=)bAsh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}