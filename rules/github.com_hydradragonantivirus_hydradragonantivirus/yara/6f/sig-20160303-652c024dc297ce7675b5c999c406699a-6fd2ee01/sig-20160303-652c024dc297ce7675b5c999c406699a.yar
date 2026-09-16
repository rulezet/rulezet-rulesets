rule sig_20160303_652c024dc297ce7675b5c999c406699a {
  meta:
    description = "datamaliciousorder - file 20160303_652c024dc297ce7675b5c999c406699a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13c8a6dcae21600ac0a7b73fd5c6660e46d2a6234f2a9c0bc08ae27377faf9c4"

  strings:
    $s1  = "var xAQnJ = \"NtURsE FYI pt.Shell xsEqLtj Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var tU = true  , EpKa = Ptz[7] + \"\" + Ptz[9];" fullword ascii
    $s3  = "var Ptz = (QVI + \"TTP\" + \" WQngbkl AnaGZ XML ream St ksYclxus AD zucNVPC OD\").split(\" \");" fullword ascii
    $s4  = "return aVjgtdf[0] + aVjgtdf[2] + aVjgtdf[4] + \".F\" + aVjgtdf[7] + aVjgtdf[9] + aVjgtdf[12] + aVjgtdf[14];" fullword ascii
    $s5  = "hxQbF.open(BzmsB,pqFpb,false);" fullword ascii
    $s6  = "return new ActiveXObject(TphCST);" fullword ascii
    $s7  = "function ipvjUhv(sltT) {" fullword ascii
    $s8  = "function idzT(ZsnVj) {" fullword ascii
    $s9  = "function jGEx(cbzte) {" fullword ascii
    $s10 = "if (((new Date())>0,7817948888)) {" fullword ascii
    $s11 = "return RmZY.responseBody;" fullword ascii
    $s12 = "if(d>=M.length) {break;}" fullword ascii
    $s13 = "return HVEtt;" fullword ascii
    $s14 = "function cJuCCJHDt(WzjrE,YgtQo,hIwxk) {" fullword ascii
    $s15 = "function EZrglgFG() {" fullword ascii
    $s16 = "function oRqe(LMrTc) {" fullword ascii
    $s17 = "if (ZsnVj == 928-728){return true;} else {return false;}" fullword ascii
    $s18 = "function REOK(zVoIE) {" fullword ascii
    $s19 = "return BHuPA.status;" fullword ascii
    $s20 = "function CDBzKdzKU(NuxXqqEOzVU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}