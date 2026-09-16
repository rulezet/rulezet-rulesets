rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50328f0c6e38a7c96b414401f867dc6bc4a3098033fb7158de56d111a9291c87"

  strings:
    $s1 = "KIbe&5" fullword ascii
    $s2 = "3,%OBoL" fullword ascii
    $s3 = ";]\"kaKI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}