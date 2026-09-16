rule Virus_Hijack_Gen_Trojan_ShellObject_g9Z_aSb8tSc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g9Z@aSb8tSc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de60740da9ee43efcd4df3391ebbf6e2380cb88396812abebb373c0c3636b853"

  strings:
    $s1 = "Bluethroat" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}