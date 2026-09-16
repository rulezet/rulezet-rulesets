rule sig_20160405_82aaf30cb0695b787cd724098abd6d28 {
  meta:
    description = "datamaliciousorder - file 20160405_82aaf30cb0695b787cd724098abd6d28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60cb05384e18e608078a5c03031bea36369bdbd57560572e50aec7d6a3e6a6bd"

  strings:
    $s1  = "var xO = true  , nkIx = EwW[7] + EwW[9] + EwW[11];" fullword ascii
    $s2  = "return ixtVXwb[0] + ixtVXwb[2] + ixtVXwb[4] + \".F\" + ixtVXwb[7] + ixtVXwb[9] + ixtVXwb[12] + ixtVXwb[14];" fullword ascii
    $s3  = "var EwW = (\"2.XMLHTTP ZoECcEQ xMjDP XML ream St cxhXOhoe AD NQNusAA O XYlq D\").split(\" \");" fullword ascii
    $s4  = "pvPi.open(BwrQH,MDLts,false);" fullword ascii
    $s5  = "if (BXqTx > 185092-300){return true;} else {return false;}" fullword ascii
    $s6  = "function QmqU(bCWkm) {" fullword ascii
    $s7  = "return LWDfa.status;" fullword ascii
    $s8  = "function gVbBa(yoNvElCg,qBrQ) {" fullword ascii
    $s9  = "function rSAYE(sZvfNo) {" fullword ascii
    $s10 = "pxZ = Z; break; " fullword ascii
    $s11 = "function ecbohz(JUPZ,JohlUl) {" fullword ascii
    $s12 = "return YGZJwBw(MU,sGvKL[399-393]+sGvKL[723-716]+sGvKL[558-550]);" fullword ascii
    $s13 = "return gqP.split(GHHiA);" fullword ascii
    $s14 = "if (wgXHF == 838-638){return true;} else {return false;}" fullword ascii
    $s15 = "return new ActiveXObject(dXlo);" fullword ascii
    $s16 = "function gRlkyFmQ(nhl) {" fullword ascii
    $s17 = "return cWda[ttzbzc[0]];" fullword ascii
    $s18 = "return \"BiydMIwbFPGkuj\";" fullword ascii
    $s19 = "function OYwlMUTo(wggP) {" fullword ascii
    $s20 = "function IFXb(jFYKx,EhJtW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}