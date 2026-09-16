rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aSlVvue_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b152b0d7b72e6533cf64fa984e23a90cfeee970d37159028ef43d55bac373b3"

  strings:
    $s1 = "uPGo;5L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}