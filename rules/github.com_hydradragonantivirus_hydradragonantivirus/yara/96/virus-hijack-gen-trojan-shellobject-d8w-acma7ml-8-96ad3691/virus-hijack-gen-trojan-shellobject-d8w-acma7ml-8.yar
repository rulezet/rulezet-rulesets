rule Virus_Hijack_Gen_Trojan_ShellObject_D8W_aCma7ml_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed9e3d4408f42587abb812d859f40496d4147c25d438dbffd0393cf81d6105cd"

  strings:
    $s1 = "}!DOxa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}