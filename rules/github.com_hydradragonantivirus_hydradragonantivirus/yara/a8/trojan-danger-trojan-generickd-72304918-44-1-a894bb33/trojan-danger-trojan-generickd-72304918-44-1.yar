rule Trojan_Danger_Trojan_GenericKD_72304918_44_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19f651a184d43bcd85c648a6c7873c5541ce4197f6464c2fe9e2ca7831a72a61"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}