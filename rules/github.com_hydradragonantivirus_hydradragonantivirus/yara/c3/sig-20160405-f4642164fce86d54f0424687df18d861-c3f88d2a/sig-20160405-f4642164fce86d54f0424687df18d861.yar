rule sig_20160405_f4642164fce86d54f0424687df18d861 {
  meta:
    description = "datamaliciousorder - file 20160405_f4642164fce86d54f0424687df18d861.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c195631d5e612c15885c111caae854d3ce5833fbd44966fdb03f5eb1a6fc05a"

  strings:
    $s1  = "var rp = true  , dIHz = BkC[7] + BkC[9] + BkC[11];" fullword ascii
    $s2  = "return fWmbzxU[0] + fWmbzxU[2] + fWmbzxU[4] + \".F\" + fWmbzxU[7] + fWmbzxU[9] + fWmbzxU[12] + fWmbzxU[14];" fullword ascii
    $s3  = "var BkC = (\"2.XMLHTTP ZLLSmMV XPWDQ XML ream St dlSIWhzS AD WCKbbrf O Fvqu D\").split(\" \");" fullword ascii
    $s4  = "NEGO.open(kpXmb,NyPBu,false);" fullword ascii
    $s5  = "if(x>=Y.length) {break;}" fullword ascii
    $s6  = "return PcXb[zvfLZL[0]];" fullword ascii
    $s7  = "function MEdK(HtbGn,qfWnd) {" fullword ascii
    $s8  = "function hVRg(yomKs,NyPBu,kpXmb) {" fullword ascii
    $s9  = "return lqMQ;" fullword ascii
    $s10 = "function FRtM(ZiTHg) {" fullword ascii
    $s11 = "if (BcBAg == 968-768){return true;} else {return false;}" fullword ascii
    $s12 = "return gtL.size;" fullword ascii
    $s13 = "function RyNkEZAkI(zmetW) {" fullword ascii
    $s14 = "function njTk(kmVxF) {" fullword ascii
    $s15 = "function SsBhYSt(ReYk,SyxRT) {" fullword ascii
    $s16 = "function XkRnp(WfMQGyPM,VCxQ) {" fullword ascii
    $s17 = "function OgFUBC(SBUK,KNuNiU) {" fullword ascii
    $s18 = "var BAyMCFt = \"vfTNCq*cQQ*pt.S\"+\"hell*FaKNucI*Scri*\";" fullword ascii
    $s19 = "return DcbDE;" fullword ascii
    $s20 = "function Xxkixcvz(xBVK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}