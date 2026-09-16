rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b0f8d43d73b026bfd7c77295f7fcbe91c69ff0824e99958c49e5412c592c83e"

  strings:
    $s1 = "Bruntime error " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}