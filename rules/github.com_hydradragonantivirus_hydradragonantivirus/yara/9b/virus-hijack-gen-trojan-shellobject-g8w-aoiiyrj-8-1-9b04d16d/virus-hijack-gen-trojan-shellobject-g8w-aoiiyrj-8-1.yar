rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOIIYRj_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOIIYRj_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d74b85d646feda822c37e75a040d6f78c5bb77a2bff573cd1b979a6cee24e14a"

  strings:
    $s1 = "DAMa!:+w" fullword ascii
    $s2 = "WanD]C,.a" fullword ascii
    $s3 = "t;MAnD" fullword ascii
    $s4 = "bAaL ]" fullword ascii
    $s5 = "G:TAnE" fullword ascii
    $s6 = "crOc$8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}