rule Trojan_Danger_Trojan_GenericKD_72304918_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49bda4de8401c242e257e1809620fa81bc77395f15edb099717d80f08fca06f2"

  strings:
    $s1 = "A;GeRS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}