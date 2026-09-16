rule sig_20151217_551400094992782ccd41fb4a8eda13f7 {
  meta:
    description = "datamaliciousorder - file 20151217_551400094992782ccd41fb4a8eda13f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df66f8b6dfde6eca27e45f68728171fa293d0e6b970ad9d03ff39ff1bfec5c6a"

  strings:
    $s1  = "function NnpuiUUMRaMjQLnXU(KokiG){pSWyxGhTOMN= '';woxIqmCkfAu=Math.round((Math.pow(Math.sin(499), 2) + Math.pow(Math.cos(499), 2" ascii
    $s2  = "ow(Math.cos(161), 2) - 1)));} EwLSBOWLm[woxIqmCkfAu]++;}woxIqmCkfAu++;} return pSWyxGhTOMN}" fullword ascii
    $s3  = "th.pow(Math.cos(941), 2) - 1)); while(true) { if(EwLSBOWLm[woxIqmCkfAu] > KokiG[woxIqmCkfAu].length-(-592+870)/278) { break; } i" ascii
    $s4  = ") - 1));while(true){if (woxIqmCkfAu >= (3935+355)/715){break;}EwLSBOWLm[woxIqmCkfAu]=Math.round((Math.pow(Math.sin(941), 2) + Ma" ascii
    $s5  = "function NnpuiUUMRaMjQLnXU(KokiG){pSWyxGhTOMN= '';woxIqmCkfAu=Math.round((Math.pow(Math.sin(499), 2) + Math.pow(Math.cos(499), 2" ascii
    $s6  = "function erIJOzR(LJnbRtZKGJfNcxqSZUNkqjoZGqvTBPvIHFMk) {return !sroLsUYEuVl(vOTCBdsNkOyjhIU(LJnbRtZKGJfNcxqSZUNkqjoZGqvTBPvIHFMk" ascii
    $s7  = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s8  = "function rkLFnDrPvyPpuCt(EfcBTQbUNBFvynHjv,EXyhIBGmEeNyGNByOvVIYYjKplVjIdwDfj,OvNxfsiFxCLfRFePjGQyygdsovRjrTxbCjR){eval(EfcBTQbU" ascii
    $s9  = "function vOTCBdsNkOyjhIU(CtruHbhZYdpJHqSQFqb) {return parseFloat(CtruHbhZYdpJHqSQFqb);}" fullword ascii
    $s10 = "function T(YNXcMfHiFeOr,QbGtoBtklPufRQ){YNXcMfHiFeOr.push(QbGtoBtklPufRQ);}" fullword ascii
    $s11 = "Y);return eCvxZ;}" fullword ascii
    $s12 = "function erIJOzR(LJnbRtZKGJfNcxqSZUNkqjoZGqvTBPvIHFMk) {return !sroLsUYEuVl(vOTCBdsNkOyjhIU(LJnbRtZKGJfNcxqSZUNkqjoZGqvTBPvIHFMk" ascii
    $s13 = "function PZXSjOFWbyKvUSfKjRWsCnXYNTHQiUytbNJzdADUwnZOyAqxZitFLY(ZuJPryWWvGShM,CMfoWJsAxqMTYK){ return geKlySm[kvEXhQpN[oDyqK(ZuJ" ascii
    $s14 = "function o(uZvBMTrMSEdEqu,sWPAUBGBJwOlT,smUNKrDzYaQ) {uZvBMTrMSEdEqu[sWPAUBGBJwOlT]=smUNKrDzYaQ;}" fullword ascii
    $s15 = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s16 = "function aQbTGmIZwdWl(xspsVLdFGwHyA) {return isFinite(xspsVLdFGwHyA);}" fullword ascii
    $s17 = "function rkLFnDrPvyPpuCt(EfcBTQbUNBFvynHjv,EXyhIBGmEeNyGNByOvVIYYjKplVjIdwDfj,OvNxfsiFxCLfRFePjGQyygdsovRjrTxbCjR){eval(EfcBTQbU" ascii
    $s18 = "function sroLsUYEuVl(qEJvvyQovogslY) {return isNaN(qEJvvyQovogslY);}" fullword ascii
    $s19 = "function PZXSjOFWbyKvUSfKjRWsCnXYNTHQiUytbNJzdADUwnZOyAqxZitFLY(ZuJPryWWvGShM,CMfoWJsAxqMTYK){ return geKlySm[kvEXhQpN[oDyqK(ZuJ" ascii
    $s20 = "function oDyqK(hsJCiIzetGl,DUKGXnSwhtISC,dUmzgKuY){SlUV=xCZCaFBLNJYxGAicI(hsJCiIzetGl,DUKGXnSwhtISC);eCvxZ=SlUV.toString(dUmzgKu" ascii

  condition:
    uint16(0) == 0x766b and
    8 of them
}