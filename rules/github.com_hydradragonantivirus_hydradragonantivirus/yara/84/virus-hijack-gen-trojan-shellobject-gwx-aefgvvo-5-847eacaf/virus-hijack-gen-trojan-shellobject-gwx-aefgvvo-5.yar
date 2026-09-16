rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f35ba338f59f787b968a46480173215b501292a3e114b5ba214212a203d1b5bf"

  strings:
    $s1 = "t]shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}