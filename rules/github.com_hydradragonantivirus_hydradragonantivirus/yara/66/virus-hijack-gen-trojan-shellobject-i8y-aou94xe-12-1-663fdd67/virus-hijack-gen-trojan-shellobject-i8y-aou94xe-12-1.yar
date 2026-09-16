rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "264438d952b3c411d7a336728292ed43f791f0a7936ac218e0c2c686470414a1"

  strings:
    $s1 = "Press Enter to start" fullword ascii
    $s2 = "Press Enter to restart" fullword ascii
    $s3 = "Score : " fullword ascii
    $s4 = "Esc to exit" fullword ascii
    $s5 = "You lost !" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}