rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e00e068ea5516949aa8ca9dc05f32224174c06fe852c1d005bc1abab94e4e0a"

  strings:
    $s1 = "munity" fullword ascii
    $s2 = "chipyahooa8s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}