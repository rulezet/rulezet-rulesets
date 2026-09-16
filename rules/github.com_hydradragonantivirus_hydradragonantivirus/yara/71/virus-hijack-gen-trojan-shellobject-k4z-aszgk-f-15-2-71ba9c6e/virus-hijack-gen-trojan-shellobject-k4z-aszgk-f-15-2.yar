rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f43d5378cb9e5a92a91af3e8fac0b36edfd992605c8c40a8bc2a8305ea5d8ea"

  strings:
    $s1 = "<PaPe[b" fullword ascii
    $s2 = "oCFaxEventExtended::CFaxEventExtended Can not allocate FAX_EVENT_EX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}