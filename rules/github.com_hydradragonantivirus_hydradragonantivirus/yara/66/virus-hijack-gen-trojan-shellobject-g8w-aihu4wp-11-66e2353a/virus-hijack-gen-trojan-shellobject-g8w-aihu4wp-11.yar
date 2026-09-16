rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25d733e828e9683a112aa28b569ada4e15a6dd521f1c7d421a93e97606f242fa"

  strings:
    $s1 = "3BWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}