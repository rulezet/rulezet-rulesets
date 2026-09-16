rule sig_20151217_00f12f3baba52284ae07e0aa1a01de0a {
  meta:
    description = "datamaliciousorder - file 20151217_00f12f3baba52284ae07e0aa1a01de0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecf32d4af47c7bd8c27c87ec441ac02f6aa258669eca615965ca310675efdeef"

  strings:
    $s1  = ") - 1));while(true){if (cZwjiJLIjAq >= (5592+18)/935){break;}EUdifZvfN[cZwjiJLIjAq]=Math.round((Math.pow(Math.sin(278), 2) + Mat" ascii
    $s2  = "function FIheJTMaOatIjHERy(UXfhj){AgMpEmpnwSe= '';cZwjiJLIjAq=Math.round((Math.pow(Math.sin(441), 2) + Math.pow(Math.cos(441), 2" ascii
    $s3  = "h.pow(Math.cos(278), 2) - 1)); while(true) { if(EUdifZvfN[cZwjiJLIjAq] > UXfhj[cZwjiJLIjAq].length-(-234+763)/529) { break; } if" ascii
    $s4  = "w(Math.cos(199), 2) - 1)));} EUdifZvfN[cZwjiJLIjAq]++;}cZwjiJLIjAq++;} return AgMpEmpnwSe}" fullword ascii
    $s5  = "function FIheJTMaOatIjHERy(UXfhj){AgMpEmpnwSe= '';cZwjiJLIjAq=Math.round((Math.pow(Math.sin(441), 2) + Math.pow(Math.cos(441), 2" ascii
    $s6  = "function grIIpSD(CtubmVdQJOadMcDpqThMtJEHgtyTPCGBWSzJ) {return !RhABYeIgOGl(QrpTwXoHWktKUeO(CtubmVdQJOadMcDpqThMtJEHgtyTPCGBWSzJ" ascii
    $s7  = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s8  = "function fQcDfDbKYLhusXlbaelmNrkUeErrnWqlSUBdiAXjgqMncFGTVhclks(gPVnbpKVCcEMk,bKcwwAvPvauAIz){ return SSykJgO[rXnQdMvG[MHWAJ(gPV" ascii
    $s9  = "function QrpTwXoHWktKUeO(HDuyzcUCXZQKEoZFYav) {return parseFloat(HDuyzcUCXZQKEoZFYav);}" fullword ascii
    $s10 = "function KJIqBOEkdsloPLA(LvNrsGkoeFHMFreNt,kUQEWNCRODrnqIKLnjjCMomTommARsJZeB,JDRyxLjKpUnBWGBZaugOuBJaQxabSZacImi){eval(LvNrsGko" ascii
    $s11 = "function z(fAUzyurcxnBDoJ,tYuriWzffawXQ,SSDYplDrJDn) {fAUzyurcxnBDoJ[tYuriWzffawXQ]=SSDYplDrJDn;}" fullword ascii
    $s12 = "function RhABYeIgOGl(xJURjzqgLIlRUd) {return isNaN(xJURjzqgLIlRUd);}" fullword ascii
    $s13 = "function grIIpSD(CtubmVdQJOadMcDpqThMtJEHgtyTPCGBWSzJ) {return !RhABYeIgOGl(QrpTwXoHWktKUeO(CtubmVdQJOadMcDpqThMtJEHgtyTPCGBWSzJ" ascii
    $s14 = "function fQcDfDbKYLhusXlbaelmNrkUeErrnWqlSUBdiAXjgqMncFGTVhclks(gPVnbpKVCcEMk,bKcwwAvPvauAIz){ return SSykJgO[rXnQdMvG[MHWAJ(gPV" ascii
    $s15 = "function YPDxrweLZZDjcNgNe(gmFwTaYAcm,GSVbmmDqLq) {return parseInt(gmFwTaYAcm,GSVbmmDqLq);}" fullword ascii
    $s16 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s17 = "O);return KvCDH;}" fullword ascii
    $s18 = "function H(GMVxMcGYFYJv,YRItiDaOANKYcT){GMVxMcGYFYJv.push(YRItiDaOANKYcT);}" fullword ascii
    $s19 = "function MHWAJ(WieoXWmPMry,xzoUiVgKnPMCz,QJSnjUHO){jvIC=YPDxrweLZZDjcNgNe(WieoXWmPMry,xzoUiVgKnPMCz);KvCDH=jvIC.toString(QJSnjUH" ascii
    $s20 = "function MHWAJ(WieoXWmPMry,xzoUiVgKnPMCz,QJSnjUHO){jvIC=YPDxrweLZZDjcNgNe(WieoXWmPMry,xzoUiVgKnPMCz);KvCDH=jvIC.toString(QJSnjUH" ascii

  condition:
    uint16(0) == 0x5872 and
    8 of them
}