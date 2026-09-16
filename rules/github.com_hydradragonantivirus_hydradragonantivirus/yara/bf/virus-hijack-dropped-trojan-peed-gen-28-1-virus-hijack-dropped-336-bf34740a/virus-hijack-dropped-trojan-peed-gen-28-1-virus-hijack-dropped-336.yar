import "pe"
rule _Virus_Hijack_Dropped_Trojan_Peed_Gen_28_1_Virus_Hijack_Dropped__336 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Trojan.Peed.Gen_28_1.vir, Virus.Hijack_Dropped.Trojan.Peed.Gen_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350bfe99375c5ec2a4ab35b70b4c3c83f7cdb36541b02db395bf070474cb4f42"
    hash2       = "2b536f7584f9478fe5313005273b7334b04aefc087befff7a622464cf0be9ead"

  strings:
    $s1  = "/DDE Error - conversation not established ($0%x)0Error occurred when DDE ran out of memory ($0%x)\"Unable to connect DDE convers" wide
    $s2  = "shutdown -r -t 0" fullword ascii
    $s3  = "JPEG Image File\"Unable to find a Table of Contents" fullword wide
    $s4  = "\" /D Everyone" fullword ascii
    $s5  = "), Opera(" fullword ascii
    $s6  = "Exception<t@" fullword ascii
    $s7  = "Text RA" fullword ascii
    $s8  = "key file: " fullword ascii
    $s9  = "Cannot drag a form\"An error returned from DDE  ($0%x)" fullword wide
    $s10 = "pc path: " fullword ascii
    $s11 = "), Netscape Navigator (" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "021fbc81843f674bcb6c9e3f12ba9f05" and (8 of them)
    ) or (all of them)
}