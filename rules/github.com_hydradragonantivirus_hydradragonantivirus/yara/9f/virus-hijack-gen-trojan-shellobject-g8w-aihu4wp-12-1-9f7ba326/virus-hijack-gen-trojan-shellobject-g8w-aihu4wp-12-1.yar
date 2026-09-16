rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e369318d67925ca99b0afcfb70bf223b1c0372bfdca58d9a5221768644e113a"

  strings:
    $s1 = "f:GLAM?" fullword ascii
    $s2 = "Windwos Defender" fullword wide
    $s3 = ")]BAul" fullword ascii
    $s4 = "X?SIsH" fullword ascii
    $s5 = "TorA>I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}