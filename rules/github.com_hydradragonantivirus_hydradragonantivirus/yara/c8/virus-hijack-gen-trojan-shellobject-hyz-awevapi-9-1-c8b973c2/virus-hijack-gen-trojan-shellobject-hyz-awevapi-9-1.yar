rule Virus_Hijack_Gen_Trojan_ShellObject_hyZ_aWevApi_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hyZ@aWevApi_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a78990736434e16feb2a1ce666f36862431161f4821be9112a4608eedcca87d2"

  strings:
    $s1 = "$VELa;Z" fullword ascii
    $s2 = "<]tROw" fullword ascii
    $s3 = "!R^@TyRO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}