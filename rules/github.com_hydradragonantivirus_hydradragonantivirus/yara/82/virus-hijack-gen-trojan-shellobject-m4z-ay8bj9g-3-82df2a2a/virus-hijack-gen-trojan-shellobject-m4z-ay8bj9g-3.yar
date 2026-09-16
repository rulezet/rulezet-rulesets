rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1db263b71f4eaa73689fd3b98ffdd8ec081adc5ea851045b6b8864b3552e824"

  strings:
    $s1 = "?must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}