rule Virus_Hijack_Trojan_GenericKDZ_103285_395 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_395.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22270cf6c0f32de30e44dcf82265d1cdd9a4601d20f07d210d9f0798070beeb"

  strings:
    $s1 = "\\e$BleB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}