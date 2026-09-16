rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba281d87168ddb3d00283a8272c23c1109161a4f9353a8cfc2951b8cb1bbf8c"

  strings:
    $s1 = "Unknown token: " fullword ascii
    $s2 = "Extra comma in array" fullword ascii
    $s3 = "Mismatched end and beginning of object" fullword ascii
    $s4 = "Found end of object or array without beginning" fullword ascii
    $s5 = "Outermost node must be an object or array" fullword ascii
    $s6 = "A name has to be a string" fullword ascii
    $s7 = "Missing data for value" fullword ascii
    $s8 = "Mismatched end and beginning of array" fullword ascii
    $s9 = "Can only add elements to objects and arrays" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}