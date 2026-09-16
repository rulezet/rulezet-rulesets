rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_120_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b621f932cfcadb3b2e49a9830ca10fd606aceac81778efae91809ad5335a6c6"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "jxYou must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}