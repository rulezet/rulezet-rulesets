rule sig_20160411_6fe7845989e5c421bbb73c57edb0bb1c {
  meta:
    description = "datamaliciousorder - file 20160411_6fe7845989e5c421bbb73c57edb0bb1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49f417c13615e432f777b0c8831254846eb86ffbf84f0cdfbb75e41632dfc78d"

  strings:
    $s1  = "var So = true  , djaM = Mir[7] + Mir[9] + Mir[11];" fullword ascii
    $s2  = "return PADMOSc[0] + PADMOSc[2] + PADMOSc[4] + \".F\" + PADMOSc[7] + PADMOSc[9] + PADMOSc[12] + PADMOSc[14];" fullword ascii
    $s3  = "IeCw.open(HcZIQ,BJMwY,false);" fullword ascii
    $s4  = "var Mir = (\"2.XMLHTTP nEsujAA ZkKWz XML ream St JicvHWzh AD VPevhqI O AMks D\").split(\" \");" fullword ascii
    $s5  = "if(K>=u.length) {break;}" fullword ascii
    $s6  = "function/*flED*/ZYvTSZyL(Mikhd,ZLSect) {" fullword ascii
    $s7  = "if (nxciw == 764-564){return true;} else {return false;}" fullword ascii
    $s8  = "function PZaIGZza(tVPg) {" fullword ascii
    $s9  = "function Kvcd(WYnZf,VdbSa) {" fullword ascii
    $s10 = "return XGlQH;" fullword ascii
    $s11 = "if (I >= WZQjB.length) {break;}" fullword ascii
    $s12 = "return YqTrAXs[0];" fullword ascii
    $s13 = "if (clWEl > 195621-998){return true;} else {return false;}" fullword ascii
    $s14 = "function eLeLLh(ILmw,JQiitP) {" fullword ascii
    $s15 = "function zkjB(nxciw) {" fullword ascii
    $s16 = "function gDfHVTZUq(DEXkc) {" fullword ascii
    $s17 = "function wlDi(WZQjB) {" fullword ascii
    $s18 = "function euXYYlef(pcd) {" fullword ascii
    $s19 = "function DOOph(bXOjAH) {" fullword ascii
    $s20 = "return new ActiveXObject(qsuu);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}