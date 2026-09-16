rule Virus_Hijack_Gen_Trojan_ShellObject_i4Z_a0fL_hf_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i4Z@a0fL!hf_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddeed373e0e82d5205e099699f5daaaaeff93a0c288b16a07a104e3c96e18c43"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}