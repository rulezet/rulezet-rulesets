rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50d76d3e32a76d87bcd9665a537ec07e8f1dfc42214056ce8cb436be3accf836"

  strings:
    $s1 = "BFautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}