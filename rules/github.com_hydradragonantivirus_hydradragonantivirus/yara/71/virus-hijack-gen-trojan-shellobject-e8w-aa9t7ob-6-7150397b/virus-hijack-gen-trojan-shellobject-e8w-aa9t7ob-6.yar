rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7e83703596080806e20648b3802f6663c43479841ea304e064b2477041bbd80"

  strings:
    $s1 = "lhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}