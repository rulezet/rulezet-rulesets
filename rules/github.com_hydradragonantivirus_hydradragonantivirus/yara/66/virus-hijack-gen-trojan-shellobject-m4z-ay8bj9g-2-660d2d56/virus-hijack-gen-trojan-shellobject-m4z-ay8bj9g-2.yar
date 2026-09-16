rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "300e02f500f9ade0798ec2c768b58c6d36d9d62a92e2758f2be3f0b94ef52274"

  strings:
    $s1 = "Ymust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}