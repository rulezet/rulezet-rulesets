rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2268547a83095a55249e79185ca4ebb776ef943c572daa90c493e0f235072d7c"

  strings:
    $s1 = "{(month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}