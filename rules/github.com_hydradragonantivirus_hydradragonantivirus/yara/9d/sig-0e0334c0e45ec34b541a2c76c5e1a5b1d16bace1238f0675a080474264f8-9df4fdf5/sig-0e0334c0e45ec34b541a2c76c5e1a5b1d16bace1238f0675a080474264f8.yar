rule sig_0e0334c0e45ec34b541a2c76c5e1a5b1d16bace1238f0675a080474264f8 {
  meta:
    description = "datamaliciousorder - file 0e0334c0e45ec34b541a2c76c5e1a5b1d16bace1238f0675a080474264f85ea6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e0334c0e45ec34b541a2c76c5e1a5b1d16bace1238f0675a080474264f85ea6"

  strings:
    $x1 = "return emp == needle;};var aso_ibora = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4" ascii
    $s2 = "shShell.ExpandEnvironmentStrings(\"%temp%\");var appdatadir = wshShell.ExpandEnvironmentStrings(\"%appdata%\");var path = \"Revi" ascii
    $s3 = "une_Order_Documnet#po839203.exe\";var is_temp = false;if(is_temp){" fullword ascii
    $s4 = "createElement(\"tmp\");sinema.dataType = \"bin.base64\";sinema.text = aso_ibora;var sugar = WScript.CreateObject(\"ADODB.Stream" ascii
    $s5 = "UEFERElOR1hYUEFQQURESU5HWFhQQVBBRERJTkdYWFBBUEFEREk=\";var silver = WScript.CreateObject(\"Microsoft.XMLDOM\");var sinema = silv" ascii

  condition:
    uint16(0) == 0x7274 and
    1 of ($x*) and all of them
}