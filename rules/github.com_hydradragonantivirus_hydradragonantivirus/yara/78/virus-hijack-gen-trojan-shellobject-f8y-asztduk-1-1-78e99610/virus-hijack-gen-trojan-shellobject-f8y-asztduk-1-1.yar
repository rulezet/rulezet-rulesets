rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4911a74a67d82797e3f48c00397e1794e003fc7f3d14ddaab85d4fdb56fb35c"

  strings:
    $s1 = "*,Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}