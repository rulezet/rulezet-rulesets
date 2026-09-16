rule sig_20160531_7360f47296bfc6ca22f99a8e9b8f9de4 {
  meta:
    description = "datamaliciousorder - file 20160531_7360f47296bfc6ca22f99a8e9b8f9de4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7ddfbb48d2edad8639db707f385e271c4a59083a318ce4c12d852dcf44ed991"

  strings:
    $x1  = "var UswdQhK = GetObject('winmgmts:{impersonationLevel=impersonate}').ExecQuery('Select * from Win32_Process Where Name = \\''+bQ" ascii
    $x2  = "var UswdQhK = GetObject('winmgmts:{impersonationLevel=impersonate}').ExecQuery('Select * from Win32_Process Where Name = \\''+bQ" ascii
    $s3  = "//KKfEP(WS, wscriptexe() + gettemp() + String.fromCharCode(92) + array[6] + PTQhGpMbYagYa());" fullword ascii
    $s4  = "// make \"wscript.exe\"" fullword ascii
    $s5  = "function gettemp() {" fullword ascii
    $s6  = "function pmpdLzBvLn(VSoghOTj,yZxaDSAMKlaW) {VSoghOTj.Run(yZxaDSAMKlaW, 0x1, 0x0);}" fullword ascii
    $s7  = "// %TEMP%" fullword ascii
    $s8  = "function CvvKsoJGRi() {return/*oQkVkSiTVRYUsrqpbzvXTSajtCpSAhaoLNsraXdsQSrigcVgvFadFhrslNfQlbcPccthJwQkFnEPOfuqIfyCmQBTXsPhPpYIm" ascii
    $s9  = "return WScript.CreateObject(" fullword ascii
    $s10 = "// write script to textfile" fullword ascii
    $s11 = "function wscriptexe() {" fullword ascii
    $s12 = "+){GrgAS+=SOTjdpJB.charAt(Math.floor(Math.random()*SOTjdpJB.length));}return GrgAS;}" fullword ascii
    $s13 = "return c.charAt(i);" fullword ascii
    $s14 = "WS.ExpandEnvironmentStrings(array[3] + array[4]) + String.fromCharCode(92) + array[5], true" fullword ascii
    $s15 = "return new ActiveXObject(cxjnZ('MSX&FJFvteDVH&ML2.XM&yyuijOWgexh&LHTTP',[0,2,4],'&'));" fullword ascii
    $s16 = "var AqlCBxxr = [array[15]]; // = run" fullword ascii
    $s17 = "function WkRXo(xQEfwGfz,sgzcY,HlSxaoACFf){try{xQEfwGfz.open();nRqYMjsM(xQEfwGfz);NPnIwxp(xQEfwGfz,sgzcY);oZUcOMKvZ(xQEfwGfz);fmG" ascii
    $s18 = "var a = lookup.join(array[7]);  // array[7] = '';" fullword ascii
    $s19 = "return new ActiveXObject(cxjnZ('WS&BvlPGmNKA&cript&BvlPGmNKA&.She&ll',[0,2,4,5],'&'));" fullword ascii
    $s20 = "function oZUcOMKvZ(erpzMf) {var gtUTUloYeh=[];erpzMf.position=gtUTUloYeh.length*(8648602-566);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}