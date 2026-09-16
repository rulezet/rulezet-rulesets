rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a931a06722bb1ff7ed544b08d9e7d4c329ff46d7e0cc6cc98dffff5d7a92197"

  strings:
    $s1 = "Leaders agree to review EU policies" fullword ascii
    $s2 = "Lose a little advice on obesity" fullword ascii
    $s3 = "French police move into Calais camps" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}