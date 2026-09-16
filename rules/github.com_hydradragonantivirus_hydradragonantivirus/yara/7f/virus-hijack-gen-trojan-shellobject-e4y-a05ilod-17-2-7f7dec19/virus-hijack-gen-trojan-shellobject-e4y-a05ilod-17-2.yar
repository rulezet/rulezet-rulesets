rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfdc04f87adf17dd59c2749a99d47f2728acdacad7d570460a18496fcc44a825"

  strings:
    $s1 = "q4c6de9=7<k>lmAE?DsFtuIMGL{N|}QUOT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}