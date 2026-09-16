rule sig_20160411_112f72390aef1258bcef46f9268ad649 {
  meta:
    description = "datamaliciousorder - file 20160411_112f72390aef1258bcef46f9268ad649.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095ef3a9482777c1e4a5faff7fb8e3480d66c9289632315ba14e67601e54fcd7"

  strings:
    $s1  = "function OMaoXJrW(CVE) {" fullword ascii
    $s2  = "var iV = true  , ijQe = TaV[7] + TaV[9] + TaV[11];" fullword ascii
    $s3  = "return mdMbCnx[0] + mdMbCnx[2] + mdMbCnx[4] + \".F\" + mdMbCnx[7] + mdMbCnx[9] + mdMbCnx[12] + mdMbCnx[14];" fullword ascii
    $s4  = "return CVE.size;" fullword ascii
    $s5  = "TowY.open(iHWrA,LpITS,false);" fullword ascii
    $s6  = "var TaV = (\"2.XMLHTTP iwhwdOP WRRZE XML ream St BitnXTNO AD qEKrMnX O ummM D\").split(\" \");" fullword ascii
    $s7  = "function VsDskssTu(spoFm) {" fullword ascii
    $s8  = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s9  = "function iaRkm(CnUbOUIG,Ebvw) {" fullword ascii
    $s10 = "function JYjPxLtT(fEda) {" fullword ascii
    $s11 = "function aXVSGc(uxRZrnE) {" fullword ascii
    $s12 = "if (USLGU == 577-377){return true;} else {return false;}" fullword ascii
    $s13 = "return OPgX[MWNDGRS[0]+MWNDGRS[1]];" fullword ascii
    $s14 = "function JdSf(BmpeV) {" fullword ascii
    $s15 = "return DWm[cBnS[0]](sGgGf);" fullword ascii
    $s16 = "if (f >= BmpeV.length) {break;}" fullword ascii
    $s17 = "function NKdiI(zegbwF) {" fullword ascii
    $s18 = "function bhFb(kgYRQ,xwGbV) {" fullword ascii
    $s19 = "function rUmz(qkDID,JNSuG) {" fullword ascii
    $s20 = "return xuzGdrD(aA,THioPB+YdxRc[659-651]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}