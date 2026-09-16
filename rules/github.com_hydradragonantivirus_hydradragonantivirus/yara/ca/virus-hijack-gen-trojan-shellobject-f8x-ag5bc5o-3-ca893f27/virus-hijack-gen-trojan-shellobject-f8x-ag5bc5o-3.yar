rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17933b1669bc053296184c5d3fec46996b53b73a692d10d43d4770128f56fd7b"

  strings:
    $s1 = "wzhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}