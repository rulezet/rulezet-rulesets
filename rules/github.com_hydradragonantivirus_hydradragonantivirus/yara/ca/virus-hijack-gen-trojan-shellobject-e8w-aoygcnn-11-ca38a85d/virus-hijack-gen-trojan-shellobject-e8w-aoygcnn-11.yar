rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f595e5be364766eb0ca7a8a46f0c3d174eeed297d77b73440454fe6a02b2080"

  strings:
    $s1 = "fRhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}