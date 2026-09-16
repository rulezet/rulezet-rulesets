rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a22e64973d26d382e17a451f5ca5bd2bdbbcff2d9fb16ee160fbce154061b96a"

  strings:
    $s1 = "*)What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}