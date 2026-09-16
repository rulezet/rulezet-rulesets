rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_39_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_39_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "178390552f070e1559592c148818bdbc24d707dc175adab9a2b4ff4a2408cb55"

  strings:
    $x1 = "C:\\Users\\Carol\\AppData\\Roaming\\Random\\Optional\\Launch Internet Explorer Browser.lnk" fullword wide
    $s2 = "Launch Internet Explorer Browser.exe" fullword wide
    $s3 = "Launch Internet Explorer Browser" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}