rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3c74e5a444dea4f782e1e3226f07be8e01d362bd7f294d2b6fe7e2c509acf12"

  strings:
    $s1 = "MItY?4" fullword ascii
    $s2 = "%ManY(" fullword ascii
    $s3 = "Unable to load assembly: " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}