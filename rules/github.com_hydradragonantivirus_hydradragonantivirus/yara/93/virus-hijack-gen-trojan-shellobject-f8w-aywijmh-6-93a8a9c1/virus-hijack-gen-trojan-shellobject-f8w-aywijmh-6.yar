rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26013fd212ff609f308590f8c0424255286145ccbc3d99b27a8b4b0da0094de1"

  strings:
    $s1 = "'your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}