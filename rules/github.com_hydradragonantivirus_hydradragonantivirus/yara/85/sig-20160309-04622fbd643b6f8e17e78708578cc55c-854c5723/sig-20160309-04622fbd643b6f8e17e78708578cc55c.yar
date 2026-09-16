rule sig_20160309_04622fbd643b6f8e17e78708578cc55c {
  meta:
    description = "datamaliciousorder - file 20160309_04622fbd643b6f8e17e78708578cc55c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef651f2f956155873f1b2428778dc71e7506e4b945249aa6c3bbefab506fc758"

  strings:
    $s1  = "return SyxqKHS[0] + SyxqKHS[2] + SyxqKHS[4] + \".F\" + SyxqKHS[7] + SyxqKHS[9] + SyxqKHS[12] + SyxqKHS[14];" fullword ascii
    $s2  = "var LZ = true  , Qmxh = Qpl[7] + Qpl[9] + Qpl[11];" fullword ascii
    $s3  = "GFZOp.open(avOuT,lRJdN,false);" fullword ascii
    $s4  = "var SyxqKHS = \"Sc XBTjTsC r TezQHXSGm ipting RTziJZL dpX ile jDGakMRVzryvTS System zA ESrbK Obj tfJeOJ ect qQjdwEz\".split(\" " ascii
    $s5  = "var Qpl = (\"2.XMLHTTP adEDRcC TyseV XML ream St zPuDbtUT AD emfZqIg O iIcu D\").split(\" \");" fullword ascii
    $s6  = "return dPhhp;" fullword ascii
    $s7  = "return fJUg.responseBody;" fullword ascii
    $s8  = "BQd = q; break; " fullword ascii
    $s9  = "if(q>=G.length) {break;}" fullword ascii
    $s10 = "return new ActiveXObject(lDPWOK);" fullword ascii
    $s11 = "return mgij.ExpandEnvironmentStrings(HonqA);" fullword ascii
    $s12 = "function uABh(BApMr,YErps) {" fullword ascii
    $s13 = "function uBFM(nsydm) {" fullword ascii
    $s14 = "function ENLq(Nmjxr) {" fullword ascii
    $s15 = "if (c >= Nmjxr.length) {break;}" fullword ascii
    $s16 = "return kHr.size;" fullword ascii
    $s17 = "function mPBt(IlkZH) {" fullword ascii
    $s18 = "function ixAZ(XzcfF) {" fullword ascii
    $s19 = "function xlZfUuaU(kHr) {" fullword ascii
    $s20 = "function xetuFZO(fJUg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}