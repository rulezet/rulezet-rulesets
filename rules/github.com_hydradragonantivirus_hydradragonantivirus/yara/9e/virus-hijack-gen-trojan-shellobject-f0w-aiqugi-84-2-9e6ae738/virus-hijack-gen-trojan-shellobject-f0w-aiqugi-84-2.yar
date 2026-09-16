rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_84_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_84_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7868fadbc12c3a698d10c3dcf51a91afad64b58abbeb128c15625d2f58f00ca"

  strings:
    $s1 = "command is %s" fullword ascii
    $s2 = "%s\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}