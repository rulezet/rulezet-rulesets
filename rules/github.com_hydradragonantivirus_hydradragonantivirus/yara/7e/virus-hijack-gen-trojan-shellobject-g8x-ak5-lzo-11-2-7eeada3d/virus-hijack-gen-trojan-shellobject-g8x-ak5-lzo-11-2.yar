rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a2e607b15137c7b3b674901e2d78420c7527e521c22cc9a59eb73e26c2bf89e"

  strings:
    $s1 = "\\My Shared Folder" fullword ascii
    $s2 = "Baga]s" fullword ascii
    $s3 = "`Write" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}