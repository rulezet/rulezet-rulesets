rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0094526a5dc0ca0c1c1c93a0ed96cb3cb608f2d3591a7699f1fe8e5c4b104334"

  strings:
    $s1 = "odIc!<L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}