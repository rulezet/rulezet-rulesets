rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aGN6KMb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1f1309795ba2049de569f5107cc911721160d20ae4bb52b20db928b360b868b"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}