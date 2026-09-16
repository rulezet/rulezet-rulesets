rule sig_20151217_918dcdd178b7832b7712981a2eec4555 {
  meta:
    description = "datamaliciousorder - file 20151217_918dcdd178b7832b7712981a2eec4555.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3dd8ff082d412b0a4c719ade188faf672b5a3155ea7bd540273bb2e00332c12"

  strings:
    $s1  = "w(Math.cos(9), 2) - 1)));} KeMEsMgur[NgOFoIJWLcj]++;}NgOFoIJWLcj++;} return ZYkJwXFStVY}" fullword ascii
    $s2  = "th.pow(Math.cos(527), 2) - 1)); while(true) { if(KeMEsMgur[NgOFoIJWLcj] > RtBga[NgOFoIJWLcj].length-(-365+710)/345) { break; } i" ascii
    $s3  = ") - 1));while(true){if (NgOFoIJWLcj >= (3059+769)/638){break;}KeMEsMgur[NgOFoIJWLcj]=Math.round((Math.pow(Math.sin(527), 2) + Ma" ascii
    $s4  = "function eSiajlDwphmGQmmyP(RtBga){ZYkJwXFStVY= '';NgOFoIJWLcj=Math.round((Math.pow(Math.sin(466), 2) + Math.pow(Math.cos(466), 2" ascii
    $s5  = "function eSiajlDwphmGQmmyP(RtBga){ZYkJwXFStVY= '';NgOFoIJWLcj=Math.round((Math.pow(Math.sin(466), 2) + Math.pow(Math.cos(466), 2" ascii
    $s6  = "function oBBmTgs(JEDaZeZCbxLyYFQZGoMHrcuTeddUtNKdmlgh) {return !wpvHQfDjIjt(kyqqvYNpuVvEltH(JEDaZeZCbxLyYFQZGoMHrcuTeddUtNKdmlgh" ascii
    $s7  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s8  = "function kyqqvYNpuVvEltH(DngYeYgXmUFtiJcjllH) {return parseFloat(DngYeYgXmUFtiJcjllH);}" fullword ascii
    $s9  = "function z(ubjHqKDUmlKZNj,rKFKJZtblJOWr,wRsVebTkEzP) {ubjHqKDUmlKZNj[rKFKJZtblJOWr]=wRsVebTkEzP;}" fullword ascii
    $s10 = ",'V','t','2','H','i','W','F',';','&','X','a','k','T','b','1','@','w','Y','B','H','f','Z','i','T','[','o','?','P',']','*',String." ascii
    $s11 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s12 = "function FvtAoNPfgbjRGiz(NfYZubsOtNRwYuKAm,mEPVtJOrUsSXqTNyWFSoXKmKlFweuJLper,sLpCZODkeSsFUuzDJotkPJogXZVSKBTvBvd){eval(NfYZubsO" ascii
    $s13 = "function b(QowKzngYLdnS,kleXrwdpazxjJh){QowKzngYLdnS.push(kleXrwdpazxjJh);}" fullword ascii
    $s14 = "function oBBmTgs(JEDaZeZCbxLyYFQZGoMHrcuTeddUtNKdmlgh) {return !wpvHQfDjIjt(kyqqvYNpuVvEltH(JEDaZeZCbxLyYFQZGoMHrcuTeddUtNKdmlgh" ascii
    $s15 = "function wpvHQfDjIjt(eHcBShwxfWHlfT) {return isNaN(eHcBShwxfWHlfT);}" fullword ascii
    $s16 = "N);return CJgiT;}" fullword ascii
    $s17 = "function ZbkdwIeNZcXn(MXkWmZggGJMeB) {return isFinite(MXkWmZggGJMeB);}" fullword ascii
    $s18 = "function FvtAoNPfgbjRGiz(NfYZubsOtNRwYuKAm,mEPVtJOrUsSXqTNyWFSoXKmKlFweuJLper,sLpCZODkeSsFUuzDJotkPJogXZVSKBTvBvd){eval(NfYZubsO" ascii
    $s19 = "function nTmHX(ZEmLdzsgjWJ,eLEXaWLeEUzsT,aRSNjDlN){kPSN=viyEimOcaxXiQaXWT(ZEmLdzsgjWJ,eLEXaWLeEUzsT);CJgiT=kPSN.toString(aRSNjDl" ascii
    $s20 = "function qaJBpuTwPdyFkfUhgLPJQFpLHGbjDdwvZwFcXnICnHuiJAFcAlKaOK(PpUqnCOdbLGjI,NfXfOadpNRRRWd){ return JRCbpDH[jsnhPKzc[nTmHX(PpU" ascii

  condition:
    uint16(0) == 0x736a and
    8 of them
}