rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fcfa164ab58dfd7a1dfca8975560269b9b098c3bb5c5135ca78c2733fed2ac7"

  strings:
    $s1 = "Welcome to use storm ddos" fullword ascii
    $s2 = "Storm ddos Server" fullword ascii
    $s3 = "Program Files\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}