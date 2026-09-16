rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_23_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7c9e0bba10b853dd183f2c6b732bd0e1001f1a7b455007dc3022ff465b7797f"

  strings:
    $s1 = "(Chinhu-Chakasenderwa Service Message DLL" fullword ascii
    $s2 = "Chinhu-Chakasenderwa Service Message DLL" fullword wide
    $s3 = "3Gogo1000 Was Also Here.Xmu\\[7xXJn\\&-8F!U~GHu7\\+JS\"%" fullword ascii
    $s4 = "\"Gogo1000 Was Here! Disc: gogo#3940" fullword ascii
    $s5 = "Gogo1000 Was Also Here" fullword ascii
    $s6 = "MY WIFE" fullword ascii
    $s7 = "\"Btw dont try to deobfuscate pls :(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}