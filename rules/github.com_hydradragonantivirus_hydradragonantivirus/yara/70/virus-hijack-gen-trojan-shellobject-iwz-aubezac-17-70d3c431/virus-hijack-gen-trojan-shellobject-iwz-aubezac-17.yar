rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba2ffbaa01d66a929947bc8e1005d413d0527a3b8d07c9337bf512c742f0d4dd"

  strings:
    $s1 = "Cvautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}