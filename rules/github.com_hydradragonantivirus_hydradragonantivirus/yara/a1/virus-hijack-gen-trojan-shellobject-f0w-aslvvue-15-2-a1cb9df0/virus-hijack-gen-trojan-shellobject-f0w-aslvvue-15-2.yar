rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aSlVvue_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5b3adc54fab9693f6e58093120f62aef186adbf34351bb6f03ba2cd038246d8"

  strings:
    $s1 = "qUAn&!C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}