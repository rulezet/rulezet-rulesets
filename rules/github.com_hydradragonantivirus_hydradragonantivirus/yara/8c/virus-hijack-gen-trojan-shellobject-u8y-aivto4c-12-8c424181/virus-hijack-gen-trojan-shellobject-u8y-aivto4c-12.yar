rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152ab30a0b7ad990c1c546b467defc91095f86a2cc8f0718dfb80e61ddb09e34"

  strings:
    $s1 = "cUbi$C0Lr0@" fullword ascii
    $s2 = "cUbE!@|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}