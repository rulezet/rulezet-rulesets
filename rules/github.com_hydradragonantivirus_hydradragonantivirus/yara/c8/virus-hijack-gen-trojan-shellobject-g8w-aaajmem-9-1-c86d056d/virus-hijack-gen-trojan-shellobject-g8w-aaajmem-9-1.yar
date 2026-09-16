rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b8f5b1f5cc9ce2cbab3ac9bf4ce1f068f3ce06c31285d0dfb673903ab060358"

  strings:
    $s1 = "SaGA*S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}