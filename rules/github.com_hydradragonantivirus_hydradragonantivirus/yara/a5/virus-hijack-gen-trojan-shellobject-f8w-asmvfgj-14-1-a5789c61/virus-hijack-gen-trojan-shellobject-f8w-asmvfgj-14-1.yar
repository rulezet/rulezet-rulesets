rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSmvFGj_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSmvFGj_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9ab5756805595645efb9916ca9c345aedc3c99244385b4371cd693a8f47c1ee"

  strings:
    $s1 = "<description>App1029</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}