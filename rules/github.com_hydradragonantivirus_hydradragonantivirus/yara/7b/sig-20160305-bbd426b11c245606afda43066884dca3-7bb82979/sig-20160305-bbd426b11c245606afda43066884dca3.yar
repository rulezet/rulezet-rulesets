rule sig_20160305_bbd426b11c245606afda43066884dca3 {
  meta:
    description = "datamaliciousorder - file 20160305_bbd426b11c245606afda43066884dca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee23eb38e96ec34f6d8a2930d5bd41212813d8e888bac93a417fa39ec4fbf5a"

  strings:
    $s1  = "var WOdhf = \"WQjvXm JWk pt.Shell MyToxPM Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var pM = true  , otuq = HAY[7] + \"\" + HAY[9];" fullword ascii
    $s3  = "var HAY = (adO + \"TTP\" + \" ESAHRlM fHBKf XML ream St teUvwdtG AD pNfLPTp OD\").split(\" \");" fullword ascii
    $s4  = "return qnaODSD[0] + qnaODSD[2] + qnaODSD[4] + \".F\" + qnaODSD[7] + qnaODSD[9] + qnaODSD[12] + qnaODSD[14];" fullword ascii
    $s5  = "wpjNb.open(cumfB,bHcfG,false);" fullword ascii
    $s6  = "return dfJAXtQ" fullword ascii
    $s7  = "function iUTpVdY(BmKa) {" fullword ascii
    $s8  = "return wJdMZ;" fullword ascii
    $s9  = "function EnWW(wpjNb,bHcfG,cumfB) {" fullword ascii
    $s10 = "if(i>=T.length) {break;}" fullword ascii
    $s11 = "return zHkx.responseBody;" fullword ascii
    $s12 = "return wFNKe.status;" fullword ascii
    $s13 = "function zrCgLrKf() {" fullword ascii
    $s14 = "return EQ.ExpandEnvironmentStrings(WOdhf[6]);" fullword ascii
    $s15 = "if (((new Date())>0,7841858888)) {" fullword ascii
    $s16 = "function ozYp(niRAr) {" fullword ascii
    $s17 = "function tjga(fStgu) {" fullword ascii
    $s18 = "if (fStgu > 164588-341){return true;} else {return false;}" fullword ascii
    $s19 = "function HWCdtmIPw(gPqcT,tfkOv,TIDor) {" fullword ascii
    $s20 = "function ZDiN(wYBux,QYTXe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}