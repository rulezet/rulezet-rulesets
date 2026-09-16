rule ARKBIRD_SOLG_APT_Lazarus_EPS_July_2020_1: FILE {
  meta:
    description = " Detected Lazarus EPS script for download and execute the payload in base 64"
    author      = "Arkbird_SOLG"
    id          = "244ef018-bc7b-5e10-bf65-b52fdb5ad403"
    date        = "2020-07-28"
    modified    = "2020-07-28"
    reference   = "https://twitter.com/spider_girl22/status/1287952503280082944"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-07-28/Lazarus/APT_Lazarus_EPS_July_2020_1.yar#L3-L30"
    license_url = "N/A"
    logic_hash  = "0fbd6ac10a31cc9a571e42f8696480336cd350e56ba2ffafb386f066fd53c552"
    score       = 75
    quality     = 45
    tags        = "FILE"
    hash1       = "152c620980f0fc20a6eade0f5b726b98fc28392d84ce386a5fc1b0877ef446d7"

  strings:
    $s1   = "cd /d \"%appdata%\\Microsoft\\Internet Explorer\""
    $s2   = "Function Base64Decode(ByVal vCode)"
    $s3   = "CreateObject(\"Msxml2.DOMDocument.3.0\")"
    $s4   = "Function BinaryToString(Binary)"
    $s5   = "CreateObject(\"ADODB.Stream\")"
    $s6   = "CreateObject(\"WScript.Shell\")"
    $s7   = "createobject(\"Microsoft.XMLHTTP\")"
    $s8   = ".Environment(\"PROCESS\")(\"ProgramW6432\") = \"\""
    $s9   = ":CreateObject(\"Scripting.FileSystemObject\").DeletefFile Wscript.ScriptFullName, True>\""
    $s10  = " echo start /B /min cscript.exe"
    $s11  = "\"^&del \"%~f0\">"
    $s12  = ".Run \"regsvr32.exe /s "
    $s13  = ".Type = 1:.Open:.Write Binary:.Position = 0:.Type = 2:.CharSet = \"us-ascii\""
    $s14  = ".Open \"GET\", "
    $s15  = "start /B /min "
    $URL1 = { 22 68 74 74 70 3A 2F 2F 74 ?? ?? ?? }
    $URL2 = { 22 68 74 74 70 73 3A 2F 2F 74 ?? ?? ?? }

  condition:
    uint16(0) == 0x33c9 and filesize < 3KB and (1 of ($URL*)) and (12 of ($s*))
}