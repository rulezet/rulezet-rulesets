rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_amCvSwc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@amCvSwc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ceec2f98a028f0b8ebbcda67fcc676c48675505c54e13813c82bb0f71a5fd3"

  strings:
    $s1 = "vUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}