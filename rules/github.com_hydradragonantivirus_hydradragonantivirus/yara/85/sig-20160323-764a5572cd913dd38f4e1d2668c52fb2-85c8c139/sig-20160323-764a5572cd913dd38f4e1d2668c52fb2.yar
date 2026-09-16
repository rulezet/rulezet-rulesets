rule sig_20160323_764a5572cd913dd38f4e1d2668c52fb2 {
  meta:
    description = "datamaliciousorder - file 20160323_764a5572cd913dd38f4e1d2668c52fb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf82461c1197b168a601c2af03655832e80174fef271b7b82737000338e1d689"

  strings:
    $s1  = "return WScript.CreateObject(UMIhw);" fullword ascii
    $s2  = "return zxPkWuM[0] + zxPkWuM[2] + zxPkWuM[4] + \".F\" + zxPkWuM[7] + zxPkWuM[9] + zxPkWuM[12] + zxPkWuM[14];" fullword ascii
    $s3  = "var Vc = true  , PIps = KjP[7] + KjP[9] + KjP[11];" fullword ascii
    $s4  = "var KjP = (\"2.XMLHTTP QKfzdql dggjv XML ream St qReWdaqV AD nfKGPPE O KaaU D\").split(\" \");" fullword ascii
    $s5  = "var zxPkWuM = ncOlJ(eTzPKjTMNS+\" \"+\"System dn uiZTr Obj zuMEce ect KkBUabw LaVxh\", \" \");" fullword ascii
    $s6  = "IpQl.open(majki,xbdYJ,false);" fullword ascii
    $s7  = "if(L>=n.length) {break;}" fullword ascii
    $s8  = "function aYJIFVv(paNG) {" fullword ascii
    $s9  = "function YUVG(bjucJ) {" fullword ascii
    $s10 = "if (TMdGO == 947-747){return true;} else {return false;}" fullword ascii
    $s11 = "function FBjSJWP(Hvaz,SZgMw) {" fullword ascii
    $s12 = "if (emLpy > 171108-287){return true;} else {return false;}" fullword ascii
    $s13 = "function lNCy(Bggvm,odfcI) {" fullword ascii
    $s14 = "return FBjSJWP(mO,zyIMI[822-816]+zyIMI[718-711]+zyIMI[227-219]);" fullword ascii
    $s15 = "function bAohgGNj(CdUU) {" fullword ascii
    $s16 = "function RFGE(emLpy) {" fullword ascii
    $s17 = "function BuTr(ggjKL,xbdYJ,majki) {" fullword ascii
    $s18 = "function gHOBCisd(nvQ) {" fullword ascii
    $s19 = "function mEzc(UMIhw) {" fullword ascii
    $s20 = "oVo = L; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}