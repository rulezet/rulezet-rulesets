rule Trojan_Danger_Trojan_GenericKD_72853156_196_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58ff0a87b00f2aef087d0722b2303fcc026fa6d7b295f38c5a9dfabaaad7cb82"

  strings:
    $s1  = "y Descript" fullword ascii
    $s2  = " Complete ~ L" fullword ascii
    $s3  = "c thread gt" fullword ascii
    $s4  = "exit deu" fullword ascii
    $s5  = "[] closure" fullword ascii
    $s6  = "August#ulCJune]" fullword ascii
    $s7  = "File!Module" fullword ascii
    $s8  = "adLibrar*Write" fullword ascii
    $s9  = "e(Open" fullword ascii
    $s10 = "`dynamic" fullword ascii
    $s11 = " Class Hier" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}