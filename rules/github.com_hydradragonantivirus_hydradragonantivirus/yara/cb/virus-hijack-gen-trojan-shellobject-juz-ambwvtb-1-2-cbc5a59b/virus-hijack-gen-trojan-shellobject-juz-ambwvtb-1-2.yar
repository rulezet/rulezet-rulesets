rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_amBwvTb_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@amBwvTb_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb5bd994b39416cbbc3af3a682b636958efae63e65a2d69740e66dcc42510864"

  strings:
    $s1 = "hUbB<>kB;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}