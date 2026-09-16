rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7ac94c054087a764a560965714393222d7ef8afcffc21eed389b759e5614de"

  strings:
    $s1 = "ywhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}