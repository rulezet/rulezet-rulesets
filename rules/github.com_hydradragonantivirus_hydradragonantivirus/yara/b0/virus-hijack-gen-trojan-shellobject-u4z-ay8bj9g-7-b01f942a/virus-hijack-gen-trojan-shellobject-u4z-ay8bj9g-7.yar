rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c550b6199379ac7938495a08f97bf82d712895477e052d0b6ff61ba3c363a2"

  strings:
    $s1 = "Internal Compiler Bug: No runtime type matcher." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}