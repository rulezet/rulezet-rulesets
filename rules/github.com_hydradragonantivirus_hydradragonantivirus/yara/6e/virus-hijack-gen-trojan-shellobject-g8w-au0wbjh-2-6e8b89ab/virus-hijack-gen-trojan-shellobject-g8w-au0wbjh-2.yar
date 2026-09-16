rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_au0WBJh_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@au0WBJh_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "121f40e52a527250017e308e68bf16e438e038e8bfc507ce313c7bbb2a1afe2b"

  strings:
    $s1 = "6|orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}