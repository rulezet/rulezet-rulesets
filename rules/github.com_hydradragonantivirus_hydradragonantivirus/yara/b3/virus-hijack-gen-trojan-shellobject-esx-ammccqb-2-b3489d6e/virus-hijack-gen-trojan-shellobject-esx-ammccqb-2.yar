rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfeb2a8756e970e03f2d850e75de10e5c92285b46cde51c9431860437b91632"

  strings:
    $s1 = ";Bwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}