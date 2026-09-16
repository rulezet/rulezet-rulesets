rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_19_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b3791c612c32d6bd117866023b63054b430813f4000407e9720b53be9c508b3"

  strings:
    $s1 = "munity" fullword ascii
    $s2 = "chipyahooa8s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}