rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b07d85538bb4667d0023fa9755d360704b4a0c1de502d2bd5faa69d6ae815968"

  strings:
    $s1 = "^remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}