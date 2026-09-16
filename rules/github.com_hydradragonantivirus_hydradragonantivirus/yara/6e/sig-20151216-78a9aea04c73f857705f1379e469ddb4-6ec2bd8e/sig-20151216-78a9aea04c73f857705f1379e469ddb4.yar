rule sig_20151216_78a9aea04c73f857705f1379e469ddb4 {
  meta:
    description = "datamaliciousorder - file 20151216_78a9aea04c73f857705f1379e469ddb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "633b1a19519bdee208e4bdc0544ae1e555f75642e6a8f834fd9908726e6b8458"

  strings:
    $s1  = "h.pow(Math.cos(340), 2) - 1)); while(true) { if(TLzZGTkCh[cIEhGwXPaTp] > ZQlAH[cIEhGwXPaTp].length-(92+89)/181) { break; } if (o" ascii
    $s2  = "function qzObMKemxMxemELzD(ZQlAH){JnXpywWrYbC= '';cIEhGwXPaTp=Math.round((Math.pow(Math.sin(675), 2) + Math.pow(Math.cos(675), 2" ascii
    $s3  = ") - 1));while(true){if (cIEhGwXPaTp >= (280+470)/125){break;}TLzZGTkCh[cIEhGwXPaTp]=Math.round((Math.pow(Math.sin(340), 2) + Mat" ascii
    $s4  = "(Math.cos(573), 2) - 1)));} TLzZGTkCh[cIEhGwXPaTp]++;}cIEhGwXPaTp++;} return JnXpywWrYbC}" fullword ascii
    $s5  = "function qzObMKemxMxemELzD(ZQlAH){JnXpywWrYbC= '';cIEhGwXPaTp=Math.round((Math.pow(Math.sin(675), 2) + Math.pow(Math.cos(675), 2" ascii
    $s6  = "function oPLPuqn(bebBOTDbbFjjMjxyetscJKxjByVsSUkQZrim) {return !WLHNfJDsttS(PziMpDjfeAdmVlI(bebBOTDbbFjjMjxyetscJKxjByVsSUkQZrim" ascii
    $s7  = "function H(LYTvXUggXJPi,DhEGJUXlPrHAac){LYTvXUggXJPi.push(DhEGJUXlPrHAac);}" fullword ascii
    $s8  = "function pEBTLYKLBUEiisPEV(MCYoVSoojf,rLyJPUmJZh) {return parseInt(MCYoVSoojf,rLyJPUmJZh);}" fullword ascii
    $s9  = "function h(YblxIAKubHHymr,rTzEvsxmrjozs,bvQFkSDUadH) {YblxIAKubHHymr[rTzEvsxmrjozs]=bvQFkSDUadH;}" fullword ascii
    $s10 = "function WLHNfJDsttS(ZyrzWikCBtTIKd) {return isNaN(ZyrzWikCBtTIKd);}" fullword ascii
    $s11 = "function DIIegsAUDpaTXtR(rLWjGtfHxBBIaWDkj,aIMSHeWovIrpLCTKiVuAaazarBHZXVfsOC,oZinXcEdaLQNeMDzTDmHoKoxoewCHCHKPkH){eval(rLWjGtfH" ascii
    $s12 = "function PSVHr(xgMnjwTzxpq,FxFeftuvjTQsj,aZmWzLdz){rBVa=pEBTLYKLBUEiisPEV(xgMnjwTzxpq,FxFeftuvjTQsj);lssxZ=rBVa.toString(aZmWzLd" ascii
    $s13 = "function PSVHr(xgMnjwTzxpq,FxFeftuvjTQsj,aZmWzLdz){rBVa=pEBTLYKLBUEiisPEV(xgMnjwTzxpq,FxFeftuvjTQsj);lssxZ=rBVa.toString(aZmWzLd" ascii
    $s14 = "z);return lssxZ;}" fullword ascii
    $s15 = "function jDTxLRaJTFNcoGbSQjYXONIOSehveADFBBfjxvQCSKlsDmmfQBqAkZ(aVIFAGctqiJZc,JiMeuzZntgTowo){ return rPeYcXp[JpkrlCHI[PSVHr(aVI" ascii
    $s16 = "function oPLPuqn(bebBOTDbbFjjMjxyetscJKxjByVsSUkQZrim) {return !WLHNfJDsttS(PziMpDjfeAdmVlI(bebBOTDbbFjjMjxyetscJKxjByVsSUkQZrim" ascii
    $s17 = "function DIIegsAUDpaTXtR(rLWjGtfHxBBIaWDkj,aIMSHeWovIrpLCTKiVuAaazarBHZXVfsOC,oZinXcEdaLQNeMDzTDmHoKoxoewCHCHKPkH){eval(rLWjGtfH" ascii
    $s18 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s19 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s20 = "function jDTxLRaJTFNcoGbSQjYXONIOSehveADFBBfjxvQCSKlsDmmfQBqAkZ(aVIFAGctqiJZc,JiMeuzZntgTowo){ return rPeYcXp[JpkrlCHI[PSVHr(aVI" ascii

  condition:
    uint16(0) == 0x704a and
    8 of them
}