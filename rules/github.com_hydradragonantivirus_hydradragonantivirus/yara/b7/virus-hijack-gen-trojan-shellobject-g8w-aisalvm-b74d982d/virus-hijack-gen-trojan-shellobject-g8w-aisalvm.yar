rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiSalvm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiSalvm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f18f709e7bb5812c41d5f62f0b0c8fb5a1a5e807fdcea80b58f9ee7e608066e"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number `" fullword ascii
    $s2 = "smust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}