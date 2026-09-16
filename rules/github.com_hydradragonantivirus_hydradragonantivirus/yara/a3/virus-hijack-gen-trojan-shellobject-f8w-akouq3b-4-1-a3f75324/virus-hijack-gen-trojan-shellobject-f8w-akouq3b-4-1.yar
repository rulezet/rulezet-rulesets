rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f481a12f02cec042cdd7594fa0697835894828df9e2f3d4a1ac25c0249b1826d"

  strings:
    $s1 = "On&Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}