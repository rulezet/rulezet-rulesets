rule sig_20160303_093263188898a25bc2337ca49ebf29ed {
  meta:
    description = "datamaliciousorder - file 20160303_093263188898a25bc2337ca49ebf29ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6edf1131d6f4c1886dee536326009af3b579cfb4f4dab8aa1eaff08d6b27ce6a"

  strings:
    $s1  = "var AjODQ = \"AQtImK ETv pt.Shell ytUFmWG Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var Xug = (Snc + \"TTP\" + \" QeHuTVi pXkaH XML ream St PQQDRPkF AD KOfSEhV OD\").split(\" \");" fullword ascii
    $s3  = "return PpJbruT[0] + PpJbruT[2] + PpJbruT[4] + \".F\" + PpJbruT[7] + PpJbruT[9] + PpJbruT[12] + PpJbruT[14];" fullword ascii
    $s4  = "var es = true  , Guug = Xug[7] + \"\" + Xug[9];" fullword ascii
    $s5  = "PsrCE.open(xvdRT,DqIKr,false);" fullword ascii
    $s6  = "var PpJbruT = \"Sc xxXaAGX r PPARrcJPQ ipting QDlTJzV GDr ile pRZzxtsxKUsuOq System wn XKwHp Obj prSEts ect TQvXdUv\".split(\" " ascii
    $s7  = "if (((new Date())>0,7578474888)) {" fullword ascii
    $s8  = "function cHSp(eKvJo) {" fullword ascii
    $s9  = "return foga.responseBody;" fullword ascii
    $s10 = "return ZW.ExpandEnvironmentStrings(AjODQ[6]);" fullword ascii
    $s11 = "function TRFwFenX() {" fullword ascii
    $s12 = "return new ActiveXObject(SSvNTR);" fullword ascii
    $s13 = "function OwCfb(SSvNTR) {" fullword ascii
    $s14 = "return GWAam;" fullword ascii
    $s15 = "function fxzw(YrMZs) {" fullword ascii
    $s16 = "function fXYyddG(VRYO) {" fullword ascii
    $s17 = "function qBurfYzWe(qONuA,GSaMG,YBYjV) {" fullword ascii
    $s18 = "return xrCBBJo" fullword ascii
    $s19 = "if (mtwLE == 516-316){return true;} else {return false;}" fullword ascii
    $s20 = "xKC = T; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}