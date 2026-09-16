rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff3ea8d4df59f0537ea082a9e368189917670119f188ea6d5e58ef11011d7ce1"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}