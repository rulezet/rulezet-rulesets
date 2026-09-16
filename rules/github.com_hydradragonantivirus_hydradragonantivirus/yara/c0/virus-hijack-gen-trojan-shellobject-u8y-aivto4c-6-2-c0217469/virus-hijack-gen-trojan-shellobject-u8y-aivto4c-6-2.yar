rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9238772499ade078b143ad6ac4e2deaf4973fd30f8a899e01eeb03e6cb741221"

  strings:
    $s1 = "0Shenzhen DriveTheLife Software Technology Co.Ltd0" fullword ascii
    $s2 = "0Shenzhen DriveTheLife Software Technology Co.Ltd1907" fullword ascii
    $s3 = "Inno Setup 1.2.10 to 6.0.2" fullword ascii
    $s4 = "Could not create output directory " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}