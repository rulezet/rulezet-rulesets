rule sig_0ffef02908f711dc3b01b83a439e2aeaafa58b021a4c930ed47772e6d958 {
  meta:
    description = "datamaliciousorder - file 0ffef02908f711dc3b01b83a439e2aeaafa58b021a4c930ed47772e6d958931e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffef02908f711dc3b01b83a439e2aeaafa58b021a4c930ed47772e6d958931e"

  strings:
    $x1 = "return emp == needle;};var aso_ibora = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4" ascii
    $s2 = "ndEnvironmentStrings(\"%temp%\");var appdatadir = wshShell.ExpandEnvironmentStrings(\"%appdata%\");var path = \"order_document_s" ascii
    $s3 = "PO35642.exe\";var is_temp = true;if(is_temp){" fullword ascii
    $s4 = "t(\"tmp\");sinema.dataType = \"bin.base64\";sinema.text = aso_ibora;var sugar = WScript.CreateObject(\"ADODB.Stream\");sugar.Typ" ascii
    $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";var silver = WScript.CreateObject(\"Microsoft.XMLDOM\");var sinema = silver.createEle" ascii

  condition:
    uint16(0) == 0x7274 and
    1 of ($x*) and all of them
}