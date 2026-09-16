rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af295119144d752b01e40e0ae85d189f37523fc10911c3408e865e32b0619b5a"

  strings:
    $s1 = "Dirt commander dexterousl" fullword wide
    $s2 = "Migrant" fullword wide
    $s3 = "Helterskelte matchmakin acting drearines addressee" fullword wide
    $s4 = "Glen deliberatel egyptia apple" fullword wide
    $s5 = " Acknowledge finetune impoten" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}