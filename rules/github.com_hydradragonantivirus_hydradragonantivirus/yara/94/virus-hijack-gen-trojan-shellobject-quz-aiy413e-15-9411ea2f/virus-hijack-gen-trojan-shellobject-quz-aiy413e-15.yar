rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0da7e6911300382964c421ad4042f4ea33c24f47f752e4e47c035602bec2def1"

  strings:
    $s1 = "TeAM[=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}