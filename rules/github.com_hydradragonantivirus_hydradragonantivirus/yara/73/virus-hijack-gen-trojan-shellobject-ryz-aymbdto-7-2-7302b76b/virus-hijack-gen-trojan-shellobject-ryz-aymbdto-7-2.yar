rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cab6a429416420bb2904c2ac9f2e150de532bc6bfbdd5de72f0c45cd35956c6"

  strings:
    $s1 = "ft Visual Studio\\" fullword ascii
    $s2 = "Timer&" fullword ascii
    $s3 = "g#Conk" fullword ascii
    $s4 = "Copy@N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}