rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e283fe0e044170bb0fda8cb7a68d048b23a321ff081627b6327072d3a0026e5"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "About Naver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}