rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc197976f70d0110fec003a54711b78f958c273f627efe298e4c86a12a282a8b"

  strings:
    $s1  = "Choose Operation:" fullword ascii
    $s2  = "1's Complement!" fullword ascii
    $s3  = "CPU THREAD " fullword ascii
    $s4  = "CORRECT)" fullword ascii
    $s5  = "your IP is bann=}" fullword ascii
    $s6  = "metho&param" fullword ascii
    $s7  = "null,'w" fullword ascii
    $s8  = "Enter First Number:" fullword ascii
    $s9  = "Enter Second Number:" fullword ascii
    $s10 = " built " fullword ascii
    $s11 = "from p" fullword ascii
    $s12 = "?Number" fullword ascii
    $s13 = "80{tOFf" fullword ascii
    $s14 = "+,BOSE" fullword ascii
    $s15 = "~,Open" fullword ascii
    $s16 = "ow<lush" fullword ascii
    $s17 = "FILE4," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}