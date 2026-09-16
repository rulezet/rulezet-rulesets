rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8273ceec26eb83fc616cebd1685c5c7b4504423433f6be96b21fb4ca7c5c14a"

  strings:
    $s1 = "s-#}lUng" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}