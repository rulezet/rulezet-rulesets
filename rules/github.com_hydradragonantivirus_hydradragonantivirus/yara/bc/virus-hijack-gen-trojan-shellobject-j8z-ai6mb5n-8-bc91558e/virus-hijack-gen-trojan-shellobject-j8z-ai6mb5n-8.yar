rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f6f354fbb56aca3901760df6d9b82e3db159cde178e33403783151b4bba6bfb"

  strings:
    $s1 = "must re" fullword wide
    $s2 = "That Factlie very" fullword wide
    $s3 = "Copyright 2008, That Factlie very" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}