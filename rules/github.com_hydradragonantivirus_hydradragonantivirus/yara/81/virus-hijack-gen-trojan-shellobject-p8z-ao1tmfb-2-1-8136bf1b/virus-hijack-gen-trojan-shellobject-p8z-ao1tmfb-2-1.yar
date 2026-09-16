rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_aO1tmfb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de655c42cbccea9cffbc64fe92e06132199d668397aaf234f5e40eebde79f368"

  strings:
    $x1 = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm." ascii
    $s2 = "\"%s\" start \"%s\"" fullword wide
    $s3 = "05/WindowsSettings\">true</ms_windowsSettings:dpiAware></windowsSettings></application></assembly>PPADDINGXXPADDINGPADDINGXXPADD" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}