rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b09705e00cebd9b2dd016c5715efea034fe20b11089a3dd8467eb329de62672"

  strings:
    $s1 = "d>must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}