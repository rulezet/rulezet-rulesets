rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d2362a2712901098e9749296692077825d1d45d04cd554ab28dbccd5ae9679"

  strings:
    $s1  = "/C choice /C Y /N /D Y /T 1 & Del " fullword wide
    $s2  = "Select * from AntivirusProduct" fullword wide
    $s3  = "Connect : Failed" fullword wide
    $s4  = "Send : Failed" fullword wide
    $s5  = "Connect : Connected" fullword wide
    $s6  = "BeginReceive : Disconnected" fullword wide
    $s7  = "BeginReceive : Seeking BufferLength" fullword wide
    $s8  = "BeginReceive : Received Full Packet" fullword wide
    $s9  = "BeginReceive : Received Full Packet : NotEqual" fullword wide
    $s10 = "Server just pinged me" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}