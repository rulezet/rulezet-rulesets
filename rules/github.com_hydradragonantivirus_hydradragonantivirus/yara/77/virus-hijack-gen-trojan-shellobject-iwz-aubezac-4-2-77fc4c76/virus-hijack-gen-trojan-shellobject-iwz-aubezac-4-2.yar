rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c838a27a14fbcccec4f0ced21618929388ed136697492c7d66b42d732e1dff0"

  strings:
    $s1 = "L`NOLo" fullword ascii
    $s2 = "Lo<ALoe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}