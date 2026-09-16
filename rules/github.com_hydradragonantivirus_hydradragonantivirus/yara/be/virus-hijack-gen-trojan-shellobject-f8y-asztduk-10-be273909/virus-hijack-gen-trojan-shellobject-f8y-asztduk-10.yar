rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a70d86518909d38abe82153372e7ce9ba1c9d1a5dc976bfcf546ab71f5a28fa2"

  strings:
    $s1 = "Wor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}