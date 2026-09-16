rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe56c5e2942f0ff65673a85d43c259dc66f9f0f579670850b4db6c02f01d746a"

  strings:
    $s1 = "Greenstone" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}