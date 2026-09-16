rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "487014c2d0bd44bb00237979aeadef77493aaef54790f34bf837a2ffa952e458"

  strings:
    $s1 = "H2What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}