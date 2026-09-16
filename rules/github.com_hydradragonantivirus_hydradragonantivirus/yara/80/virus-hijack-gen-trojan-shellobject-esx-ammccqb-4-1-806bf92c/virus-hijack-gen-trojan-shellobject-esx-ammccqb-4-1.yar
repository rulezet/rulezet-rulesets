rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2da266ee632277f911d2143c0a825d7a37519fc98db947a25b8b47fdbd69cbc1"

  strings:
    $s1 = "You must supply a password to make this connection:" fullword wide
    $s2 = "Enter Network Access Password" fullword wide
    $s3 = "DDE Share Name:" fullword wide
    $s4 = "Out of Memory (%ld bytes needed)" fullword ascii
    $s5 = "Cancel &All" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}