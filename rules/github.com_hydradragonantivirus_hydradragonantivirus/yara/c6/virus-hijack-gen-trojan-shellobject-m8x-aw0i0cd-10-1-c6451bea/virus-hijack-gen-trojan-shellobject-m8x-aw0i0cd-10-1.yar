rule Virus_Hijack_Gen_Trojan_ShellObject_m8X_aW0I0Cd_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8X@aW0I0Cd_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61e4aea99b20a36e8d26f6a4f4147ee8ac1abb08ca247c6166a2c07154579b7"

  strings:
    $s1 = "tOWy%o" fullword ascii
    $s2 = " +,heRs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}