rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_28_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_28_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf312e1ce7e80126a9d306d56886daea8d673bcdb9484d6ef10c575da625e4e"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}