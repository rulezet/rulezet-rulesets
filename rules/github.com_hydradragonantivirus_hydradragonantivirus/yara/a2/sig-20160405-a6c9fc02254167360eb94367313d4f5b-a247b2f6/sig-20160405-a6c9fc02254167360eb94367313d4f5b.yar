rule sig_20160405_a6c9fc02254167360eb94367313d4f5b {
  meta:
    description = "datamaliciousorder - file 20160405_a6c9fc02254167360eb94367313d4f5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "144a88a8beaf75bb8569269e14f09f12b7f98adef65e1cd8f74891c4a42d65dd"

  strings:
    $s1  = "function xYXH(ruspy) {" fullword ascii
    $s2  = "var Yo = true  , Tpxg = Cps[7] + Cps[9] + Cps[11];" fullword ascii
    $s3  = "return JReubJV[0] + JReubJV[2] + JReubJV[4] + \".F\" + JReubJV[7] + JReubJV[9] + JReubJV[12] + JReubJV[14];" fullword ascii
    $s4  = "nXIS.open(OPbiG,TCvhn,false);" fullword ascii
    $s5  = "var urDBIKr = \"RCPoBd*bHk*pt.S\"+\"hell*TEDREAd*Scri*\";" fullword ascii
    $s6  = "function tRctCgW(CflV) {" fullword ascii
    $s7  = "function qSuXDZRw(tCPd) {" fullword ascii
    $s8  = "if (q >= kNkst.length) {break;}" fullword ascii
    $s9  = "function QhFMyeI(OaXu,diysg) {" fullword ascii
    $s10 = "function ZqLM(qvcMq) {" fullword ascii
    $s11 = "return \"gLpRQCKJxtifaX\";" fullword ascii
    $s12 = "return new ActiveXObject(dFyA);" fullword ascii
    $s13 = "function qXbGHM(znjrBpI) {" fullword ascii
    $s14 = "function mPaf(PWYTO) {" fullword ascii
    $s15 = "return LwiTTAZ;" fullword ascii
    $s16 = "return KLOjb;" fullword ascii
    $s17 = "function xEHyq(uPYnEy) {" fullword ascii
    $s18 = "function WJTUJzJr(drV) {" fullword ascii
    $s19 = "if(T>=G.length) {break;}" fullword ascii
    $s20 = "if (wdFtc == 1164-964){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}