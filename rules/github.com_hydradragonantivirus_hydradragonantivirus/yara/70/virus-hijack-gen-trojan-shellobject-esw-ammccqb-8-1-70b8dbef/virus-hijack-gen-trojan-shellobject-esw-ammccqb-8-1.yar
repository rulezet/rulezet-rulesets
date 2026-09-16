rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d82bff3cbdff09a36428904f0dbd22e3636846d098d39cad8e6827bebabf564f"

  strings:
    $s1 = "Welcome to use storm ddos" fullword ascii
    $s2 = "Storm ddos Server" fullword ascii
    $s3 = "Program Files\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}