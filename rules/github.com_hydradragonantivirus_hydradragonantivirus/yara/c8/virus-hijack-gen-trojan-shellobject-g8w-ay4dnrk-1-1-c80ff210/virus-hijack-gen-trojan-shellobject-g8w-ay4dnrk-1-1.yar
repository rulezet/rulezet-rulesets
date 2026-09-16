rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acf634e177e5a2f10ebeba8ae7250d143491e7af84080fb112b2c8a604042cfd"

  strings:
    $s1 = "Unpoised" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}