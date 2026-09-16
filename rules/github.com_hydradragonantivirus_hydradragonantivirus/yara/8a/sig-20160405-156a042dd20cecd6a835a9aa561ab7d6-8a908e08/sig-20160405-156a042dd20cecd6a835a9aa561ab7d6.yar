rule sig_20160405_156a042dd20cecd6a835a9aa561ab7d6 {
  meta:
    description = "datamaliciousorder - file 20160405_156a042dd20cecd6a835a9aa561ab7d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71096b446a56371240ce7ae80cca56243a40e0a68407627d1fdc0cbd676bf0e4"

  strings:
    $s1  = "return GQsqnUm[0] + GQsqnUm[2] + GQsqnUm[4] + \".F\" + GQsqnUm[7] + GQsqnUm[9] + GQsqnUm[12] + GQsqnUm[14];" fullword ascii
    $s2  = "var AT = true  , gMtK = YIz[7] + YIz[9] + YIz[11];" fullword ascii
    $s3  = "var YIz = (\"2.XMLHTTP awyffBh SWLIx XML ream St reJXFNUw AD BPHMtBc O TQwr D\").split(\" \");" fullword ascii
    $s4  = "xyDQ.open(NLBIc,FLyYD,false);" fullword ascii
    $s5  = "function YLoYEBqC(DGP) {" fullword ascii
    $s6  = "return mWbdSFm;" fullword ascii
    $s7  = "var HHQGonC = \"cVyVXs*tBj*pt.S\"+\"hell*AumoWKz*Scri*\";" fullword ascii
    $s8  = "return DGP.size;" fullword ascii
    $s9  = "if (LLPOn == 1173-973){return true;} else {return false;}" fullword ascii
    $s10 = "function aYcd(LXdrT,vAecR) {" fullword ascii
    $s11 = "if (l >= bcgjC.length) {break;}" fullword ascii
    $s12 = "function BKVe(YsRKl) {" fullword ascii
    $s13 = "return new ActiveXObject(ebBJ);" fullword ascii
    $s14 = "function YnBbOUE(tPCN) {" fullword ascii
    $s15 = "return DtTvzXO(YR,vXOOi[1004-998]+vXOOi[995-988]+vXOOi[364-356]);" fullword ascii
    $s16 = "function fvVa(frvLB) {" fullword ascii
    $s17 = "function TDqAkR(SGLV,enlTcy) {" fullword ascii
    $s18 = "function DtTvzXO(zCNE,DsVLu) {" fullword ascii
    $s19 = "return UBJSp.status;" fullword ascii
    $s20 = "function MTgK(JYBPr,FLyYD,NLBIc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}