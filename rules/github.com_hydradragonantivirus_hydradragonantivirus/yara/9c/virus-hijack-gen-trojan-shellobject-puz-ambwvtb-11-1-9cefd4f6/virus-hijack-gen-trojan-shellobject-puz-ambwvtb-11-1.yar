rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d355181f7c83504c99b1adaed5789f6f80ed166538836543d85cf4e65cef5ad"

  strings:
    $s1 = "LEAF`F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}