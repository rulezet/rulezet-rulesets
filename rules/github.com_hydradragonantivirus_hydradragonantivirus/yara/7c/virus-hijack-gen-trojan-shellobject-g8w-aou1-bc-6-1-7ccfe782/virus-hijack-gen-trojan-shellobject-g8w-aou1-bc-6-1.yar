rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d5ab9ba6dea4c9d49adfff2cb09ae618b494ca21623d5ad73a5d44a0557bf45"

  strings:
    $s1 = "[itself]" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}