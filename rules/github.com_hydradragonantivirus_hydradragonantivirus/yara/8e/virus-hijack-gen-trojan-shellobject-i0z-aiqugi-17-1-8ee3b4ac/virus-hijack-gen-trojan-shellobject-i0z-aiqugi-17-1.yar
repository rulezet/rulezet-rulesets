rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a61a0675bcbd7d4b6ff2a5c3de7a9067861d37fce1b132f5cca05a1b727b1e8"

  strings:
    $s1 = "( liVe" fullword ascii
    $s2 = "( liVe}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}