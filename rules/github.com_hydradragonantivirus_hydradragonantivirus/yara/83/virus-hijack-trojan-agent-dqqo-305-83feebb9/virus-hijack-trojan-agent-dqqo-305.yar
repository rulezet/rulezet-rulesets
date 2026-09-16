rule Virus_Hijack_Trojan_Agent_DQQO_305 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cb426b841c32ebdb37975b0b9e6c66dc47efe9476260d178fcc030958f2b4ef"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "iYou must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}