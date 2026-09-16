rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "134fca73138f0044265090d795bcd85092151ebc99326ef7080e7168b658c3e7"

  strings:
    $s1 = "Host@FA" fullword ascii
    $s2 = "5Request rejected because SOCKS server cannot connect.QRequest rejected because the client program and identd report different u" wide
    $s3 = "Exception j@" fullword ascii
    $s4 = "Server@rB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}