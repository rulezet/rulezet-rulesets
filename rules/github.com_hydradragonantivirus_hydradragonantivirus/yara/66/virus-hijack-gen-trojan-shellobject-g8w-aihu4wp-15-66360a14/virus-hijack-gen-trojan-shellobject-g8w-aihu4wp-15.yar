rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d76eca2196170484db6f589764a3cd7b3517dfb93e98e5f5d57aaa68339cbbb"

  strings:
    $s1 = "74What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}