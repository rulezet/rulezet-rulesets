rule sig_20151216_a758a4e35605e7804326d3a433a9d331 {
  meta:
    description = "datamaliciousorder - file 20151216_a758a4e35605e7804326d3a433a9d331.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2384fc8317a049c02ef131dfc647fc8fc542579b1b1c66374c2e33faf901ef4"

  strings:
    $s1  = "pow(Math.cos(443), 2) - 1)));} wHMWeHbYS[ERKBUfiMUkJ]++;}ERKBUfiMUkJ++;} return KxBvEmXkKzr}" fullword ascii
    $s2  = ") - 1));while(true){if (ERKBUfiMUkJ >= (3336+912)/708){break;}wHMWeHbYS[ERKBUfiMUkJ]=Math.round((Math.pow(Math.sin(189), 2) + Ma" ascii
    $s3  = "function WYyrHtvxkwVSOcjfs(ylwUX){KxBvEmXkKzr= '';ERKBUfiMUkJ=Math.round((Math.pow(Math.sin(253), 2) + Math.pow(Math.cos(253), 2" ascii
    $s4  = "th.pow(Math.cos(189), 2) - 1)); while(true) { if(wHMWeHbYS[ERKBUfiMUkJ] > ylwUX[ERKBUfiMUkJ].length-(105+514)/619) { break; } if" ascii
    $s5  = "XrBAxYCIURLSSkvNhTbGBOKodMannCYxkXT([ylwUX[ERKBUfiMUkJ][wHMWeHbYS[ERKBUfiMUkJ]]], Math.round((Math.pow(Math.sin(443), 2) + Math." ascii
    $s6  = "function WYyrHtvxkwVSOcjfs(ylwUX){KxBvEmXkKzr= '';ERKBUfiMUkJ=Math.round((Math.pow(Math.sin(253), 2) + Math.pow(Math.cos(253), 2" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function AwZfV(CiwAIwsBkDG,FdxNpbwklsKTE,UVZFhBJm){gykV=JPAHozReFLkUmdzzy(CiwAIwsBkDG,FdxNpbwklsKTE);xdKfE=gykV.toString(UVZFhBJ" ascii
    $s9  = "function IXAOhuNfEnrOoRwuqNcXrBAxYCIURLSSkvNhTbGBOKodMannCYxkXT(xLUYYtLcvvxRE,ubCQrFmiXThqPd){ return rwfYGGv[HDWcgiDp[AwZfV(xLU" ascii
    $s10 = "m);return xdKfE;}" fullword ascii
    $s11 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s12 = "function UDdeGkAAZVsfpcl(EXQJWDEhXxREPAqXf,PtcwOICGJGesZvXhCbmSLfoopDgFDtLTeD,HwvLJPplRoJMiIBgqQnqcmfxnVraIooIJSn){eval(EXQJWDEh" ascii
    $s13 = "function ZbuHZVOkypjt(VpqZZanpHBrHI) {return isFinite(VpqZZanpHBrHI);}" fullword ascii
    $s14 = "function JPAHozReFLkUmdzzy(XbbOLLZZUB,tIzEukMKua) {return parseInt(XbbOLLZZUB,tIzEukMKua);}" fullword ascii
    $s15 = "function UDdeGkAAZVsfpcl(EXQJWDEhXxREPAqXf,PtcwOICGJGesZvXhCbmSLfoopDgFDtLTeD,HwvLJPplRoJMiIBgqQnqcmfxnVraIooIJSn){eval(EXQJWDEh" ascii
    $s16 = "function p(iWMAEgIUsdRalV,IGMdRLKidGbqi,jqRESPwUmKa) {iWMAEgIUsdRalV[IGMdRLKidGbqi]=jqRESPwUmKa;}" fullword ascii
    $s17 = "function U(fkdMeOCXEbqq,GGuADTlNqJCIBP){fkdMeOCXEbqq.push(GGuADTlNqJCIBP);}" fullword ascii
    $s18 = "function zZfMftWfPxD(sAHHTgPvTdDQSm) {return isNaN(sAHHTgPvTdDQSm);}" fullword ascii
    $s19 = "function AwZfV(CiwAIwsBkDG,FdxNpbwklsKTE,UVZFhBJm){gykV=JPAHozReFLkUmdzzy(CiwAIwsBkDG,FdxNpbwklsKTE);xdKfE=gykV.toString(UVZFhBJ" ascii
    $s20 = "function VinzCeLaINkoGFf(xNLwpngyZaUhJZUSuRC) {return parseFloat(xNLwpngyZaUhJZUSuRC);}" fullword ascii

  condition:
    uint16(0) == 0x4448 and
    8 of them
}