rule Virus_Hijack_Trojan_EmotetU_Gen_mS0_habwjyfi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.mS0@habwjyfi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cff3898eadc35f412f0c07bd3d8e943904a830af24dd19ad9ddb41e2af77558"

  strings:
    $s1 = "preagriculture" fullword wide
    $s2 = "Eudaemonism" fullword wide
    $s3 = "Slodge" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}