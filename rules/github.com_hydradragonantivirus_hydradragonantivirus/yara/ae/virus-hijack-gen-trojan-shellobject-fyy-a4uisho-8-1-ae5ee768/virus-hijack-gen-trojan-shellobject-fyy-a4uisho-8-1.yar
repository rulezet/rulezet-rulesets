rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "054a2cc17d9a500ad31a53babcb93accbecf2730022f0c80209dd28541e8ed89"

  strings:
    $s1 = "Host@FA" fullword ascii
    $s2 = "5Request rejected because SOCKS server cannot connect.QRequest rejected because the client program and identd report different u" wide
    $s3 = "Exception j@" fullword ascii
    $s4 = "Server@rB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}