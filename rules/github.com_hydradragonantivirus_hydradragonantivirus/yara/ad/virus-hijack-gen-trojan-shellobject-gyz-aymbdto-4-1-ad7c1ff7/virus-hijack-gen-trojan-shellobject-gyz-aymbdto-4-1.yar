rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_ayMBdto_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@ayMBdto_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77ff5973beea98f4b896761721c0d73c8d7f6362831919771efb74183ac9ece1"

  strings:
    $s1 = "HCan pass constants by reference only to parameters with \"Const\" keyword." fullword wide
    $s2 = " For/Do/While loop " fullword wide
    $s3 = " \"long*\", \"int*\" " fullword wide
    $s4 = " \"short*\" " fullword wide
    $s5 = ".*Expected a variable in user function call." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}