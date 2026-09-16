rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dadee8930e3c00be5cdfb90c08733a285f84b7a694c3aa2f13ab694fd1c06926"

  strings:
    $s1 = "retro face" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}