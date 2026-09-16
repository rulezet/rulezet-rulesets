rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aGIb_Qk_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aGIb!Qk_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2002199d1f32630674b057d445105575a03b78b78e5b5983fa5df4632c8f245d"

  strings:
    $s1 = "rEcCy?_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}