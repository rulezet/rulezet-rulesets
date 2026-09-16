rule Virus_Hooker_Trojan_GenericKD_48560802_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d3409d4678e15785243d5b6484a2be0696cfd029af4a5f6de8ae8f21d9daed"

  strings:
    $s1 = "gUnL:`" fullword ascii
    $s2 = "taroc6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}