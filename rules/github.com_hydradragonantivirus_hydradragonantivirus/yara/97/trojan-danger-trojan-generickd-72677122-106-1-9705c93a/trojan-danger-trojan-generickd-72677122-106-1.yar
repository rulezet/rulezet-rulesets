rule Trojan_Danger_Trojan_GenericKD_72677122_106_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9491f4f82c9834c9276995ce35819e0524270fcb726d596945fc275430841f0b"

  strings:
    $s1 = "Decompress error" fullword ascii
    $s2 = "time 'r" fullword ascii
    $s3 = "land C+" fullword ascii
    $s4 = "FORME>6" fullword ascii
    $s5 = "FAST}Xd" fullword ascii
    $s6 = "play;<" fullword ascii
    $s7 = "B`a`file" fullword ascii
    $s8 = "Can't load function" fullword ascii
    $s9 = "Can't load library" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}