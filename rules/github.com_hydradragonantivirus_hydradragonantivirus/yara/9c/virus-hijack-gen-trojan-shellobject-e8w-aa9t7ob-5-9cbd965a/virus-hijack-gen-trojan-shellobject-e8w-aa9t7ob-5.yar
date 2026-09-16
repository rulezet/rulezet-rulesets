rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7f47e6c419afc63edae2077a84a18a0e273e008d01e73fba7132784dbdcd2b5"

  strings:
    $s1 = "Qchundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}