rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b10badc25d6fb7c5ca20668ec5c076710d3a4d5b27015444f473f18feaa355fc"

  strings:
    $s1 = "  ilia@valley.ru" fullword ascii
    $s2 = "Action(=C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}