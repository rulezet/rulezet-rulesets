rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402a5a79cf8c5d331152d86ff60c1201ec78d3874bdffe36a1f6f552b02bb351"

  strings:
    $x1 = "copy \"%s\" C:\\Users\\Public\\Photos.exe" fullword ascii
    $s2 = "copy \"%s\" C:\\WINDOWS\\Photos.exe" fullword ascii
    $s3 = "        WScript.Echo \"ERROR: Target folder not found.\"" fullword ascii
    $s4 = "copy \"%s\" %c:\\" fullword ascii
    $s5 = "    ' Write the downloaded byte stream to the target file" fullword ascii
    $s6 = "    ' Close the target file" fullword ascii
    $s7 = "    ElseIf objFSO.FolderExists( Left( myPath, InStrRev( myPath, \"\\\" ) - 1 ) ) Then" fullword ascii
    $s8 = "    objHTTP.Open \"GET\", myURL, False" fullword ascii
    $s9 = "Message from Windows !" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}