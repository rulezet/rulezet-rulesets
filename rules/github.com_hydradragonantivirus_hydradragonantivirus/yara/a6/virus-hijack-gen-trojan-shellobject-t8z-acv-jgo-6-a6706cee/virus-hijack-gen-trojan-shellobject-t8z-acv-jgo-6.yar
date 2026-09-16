rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ee4c2ee9aef30cfbfd22b3accc999035a1edbeeee97f700fec1aee4db35a93"

  strings:
    $s1 = "$virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}