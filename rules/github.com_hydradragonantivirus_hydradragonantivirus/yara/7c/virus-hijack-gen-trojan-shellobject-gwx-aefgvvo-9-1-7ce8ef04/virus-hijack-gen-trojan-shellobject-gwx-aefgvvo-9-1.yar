rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d5d28bac4dc1d113244eedad3b51757307a595a84199a3d76c29047d37928c"

  strings:
    $s1 = "Rondure" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}