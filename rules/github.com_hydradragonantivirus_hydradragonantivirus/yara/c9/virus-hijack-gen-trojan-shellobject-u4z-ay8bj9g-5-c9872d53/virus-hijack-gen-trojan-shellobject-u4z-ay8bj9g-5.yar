rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14efc5c9903f49db9fa2e62da4f623c83a6acadc382d6911896f4cd2f062afc8"

  strings:
    $s1 = "Tmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}