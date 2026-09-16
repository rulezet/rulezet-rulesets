rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_40_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36584e931eda745888cb82ec7ad727b7bce758e0b42becf19b628c001cbd1da6"

  strings:
    $s1 = "***about" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}