rule Virus_Hijack_Trojan_Agent_DQQO_214 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_214.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f1ce6118e14489f58f17ea64f58720075f5921c4d53e06c13984b5c3d334556"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "RkYou must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}