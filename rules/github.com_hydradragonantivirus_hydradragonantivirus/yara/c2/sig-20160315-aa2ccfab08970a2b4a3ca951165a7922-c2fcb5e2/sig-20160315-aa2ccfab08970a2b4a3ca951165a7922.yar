rule sig_20160315_aa2ccfab08970a2b4a3ca951165a7922 {
  meta:
    description = "datamaliciousorder - file 20160315_aa2ccfab08970a2b4a3ca951165a7922.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "421156575ee2208b16e4f1450f63ec727ee8101695b8622dea1486044a65ee9b"

  strings:
    $s1  = "return SxehUME[0] + SxehUME[2] + SxehUME[4] + \".F\" + SxehUME[7] + SxehUME[9] + SxehUME[12] + SxehUME[14];" fullword ascii
    $s2  = "var Wh = true  , ZrZB = inE[7] + inE[9] + inE[11];" fullword ascii
    $s3  = "var inE = (\"2.XMLHTTP xpuKpAw bHOkA XML ream St pZOhgwUD AD zXcEmMK O ftKb D\").split(\" \");" fullword ascii
    $s4  = "var SxehUME = ujAiH(\"Sc dJFciIp r OyymXsFOK ipting hkygipR LNz ile xMkRsIzelYbiLs System zv Vstmy Obj aZmHde ect suDbEav IvttP" ascii
    $s5  = "RTzTu.open(ahjvv,TuteX,false);" fullword ascii
    $s6  = "var SxehUME = ujAiH(\"Sc dJFciIp r OyymXsFOK ipting hkygipR LNz ile xMkRsIzelYbiLs System zv Vstmy Obj aZmHde ect suDbEav IvttP" ascii
    $s7  = "function CupF(eeqSG,PwTFg) {" fullword ascii
    $s8  = "function pUGKVZW(XIWD,FewRc) {" fullword ascii
    $s9  = "function jxucZZix() {" fullword ascii
    $s10 = "function TQGe(suXdm) {" fullword ascii
    $s11 = "function bUrd(RTzTu,TuteX,ahjvv) {" fullword ascii
    $s12 = "cux = X; break; " fullword ascii
    $s13 = "if (kfBTz == 584-384){return true;} else {return false;}" fullword ascii
    $s14 = "if(X>=a.length) {break;}" fullword ascii
    $s15 = "function CzHx(kfBTz) {" fullword ascii
    $s16 = "if (YbDje > 195623-897){return true;} else {return false;}" fullword ascii
    $s17 = "function NYFF(UEdUy) {" fullword ascii
    $s18 = "return pUGKVZW(vo,IifCZ[129-123]+IifCZ[196-189]+IifCZ[992-984]);" fullword ascii
    $s19 = "function zLmEOeB(JzLT) {" fullword ascii
    $s20 = "function dIZa(hWoWW,tgMAm) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}