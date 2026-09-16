rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "805b22c34fcd2667c68f31d1e0f09f54ab1d59dd8ddab36b403bc11835172f4c"

  strings:
    $s1 = "LITE#V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}