rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d84521e5b0d399220fee7ae19fc0e071f04bff993e1edf350711121c76202e"

  strings:
    $s1 = "5your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}