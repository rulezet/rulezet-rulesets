rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecf1c18fd8e00059f7408f943e96f73aa08839601eec0bc2588fcb3e9c29d137"

  strings:
    $s1 = "])GOeS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}