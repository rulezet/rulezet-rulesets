rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4949eb094d1c0054810f52bf15fd4d7c52fd74b51955996c08d7ca090a1c2b9b"

  strings:
    $s1 = "{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}