rule Virus_Hijack_Gen_Trojan_ShellObject_nuZ_aOFwKHc_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.nuZ@aOFwKHc_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d22427ca72fb9ef2c9d72044d9b2803db7977c43fa76fde64483e28e9a7fcba"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}