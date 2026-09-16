rule sig_20160308_0ae78f7c3ec7b71b5660c562a8d7a2da {
  meta:
    description = "datamaliciousorder - file 20160308_0ae78f7c3ec7b71b5660c562a8d7a2da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f12375cec4f1260f4d969a1e937a62145ba579166cc811caddcba7ebe3f8fa"

  strings:
    $s1  = "var Mt = true  , fHmh = KSP[7] + KSP[9] + KSP[11];" fullword ascii
    $s2  = "return TTXRATI[0] + TTXRATI[2] + TTXRATI[4] + \".F\" + TTXRATI[7] + TTXRATI[9] + TTXRATI[12] + TTXRATI[14];" fullword ascii
    $s3  = "var KSP = (\"2.XMLHTTP qRNCihc sgXOV XML ream St tLoNwDLn AD dLvfHzv O DTuV D\").split(\" \");" fullword ascii
    $s4  = "yAskp.open(XEIIX,ZPXEj,false);" fullword ascii
    $s5  = "var TTXRATI = \"Sc pOshTcj r mUtDMDxTy ipting idAQoCT QxL ile mTEmwCjDBTVGvF System LB sOKkE Obj RcxYnu ect mFjSEJD\".split(\" " ascii
    $s6  = "function vJJv(ZQNMF) {" fullword ascii
    $s7  = "function otjHSknvM(AzClFGeurJt) {" fullword ascii
    $s8  = "return RrgXf;" fullword ascii
    $s9  = "function uTNX(EgKsO,TBfkP) {" fullword ascii
    $s10 = "YSp = h; break; " fullword ascii
    $s11 = "return bUgiC.status;" fullword ascii
    $s12 = "function nVQg(YeruH) {" fullword ascii
    $s13 = "function JkgC(yAskp,ZPXEj,XEIIX) {" fullword ascii
    $s14 = "function HINp(bUgiC) {" fullword ascii
    $s15 = "if (((new Date())>0,7258131888)) {" fullword ascii
    $s16 = "return Yga.size;" fullword ascii
    $s17 = "function vYcM(OgYxb,pUfro) {" fullword ascii
    $s18 = "function yqwj(bwkUK) {" fullword ascii
    $s19 = "function zlRmavIe(Yga) {" fullword ascii
    $s20 = "function treJ(yEXLo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}