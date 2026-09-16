rule Virus_Hijack_Trojan_Agent_DQQO_133_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_133_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4484b6439c4f111e7e00923eca9b44aab9ca0848c85b99294bd38c25ddb70f96"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s2 = "Copyright (c) 2006-2019 Symantec Corporation. All rights reserved. Use of this product is subject to license terms." fullword wide
    $s3 = " )#6;9@jkKvz>HO96<4.5HHQMXe@@NOPe[}" fullword ascii
    $s4 = "Consumer Business Unit1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}