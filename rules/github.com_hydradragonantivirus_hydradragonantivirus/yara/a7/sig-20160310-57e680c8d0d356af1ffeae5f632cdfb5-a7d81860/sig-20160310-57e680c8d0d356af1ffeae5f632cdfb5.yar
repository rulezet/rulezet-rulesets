rule sig_20160310_57e680c8d0d356af1ffeae5f632cdfb5 {
  meta:
    description = "datamaliciousorder - file 20160310_57e680c8d0d356af1ffeae5f632cdfb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8094edc2852b43966c9dc7768c5231107203958f8f856d708172ae92698d3e4"

  strings:
    $s1  = "return oNTnibN[0] + oNTnibN[2] + oNTnibN[4] + \".F\" + oNTnibN[7] + oNTnibN[9] + oNTnibN[12] + oNTnibN[14];" fullword ascii
    $s2  = "var wS = true  , AWuL = xGV[7] + xGV[9] + xGV[11];" fullword ascii
    $s3  = "PWPQi.open(iCIGY,IAXqv,false);" fullword ascii
    $s4  = "var oNTnibN = \"Sc tIeevpb r gqPbzUZpG ipting WvIrQZh dCG ile xpFZMXcxdLHwjX System eq nDMbT Obj kTCgmp ect qQUIcfQ\".split(\" " ascii
    $s5  = "var xGV = (\"2.XMLHTTP vgeDMDS TZCCR XML ream St CzyQjDjH AD oodYPqx O mYdL D\").split(\" \");" fullword ascii
    $s6  = "if(W>=M.length) {break;}" fullword ascii
    $s7  = "function bquB(XUOJt) {" fullword ascii
    $s8  = "function yjWZ(sNlGo) {" fullword ascii
    $s9  = "return ZMA.size;" fullword ascii
    $s10 = "function DoUPuAEsS(UPRue,PiFkR,SSqNW,EDZD) {" fullword ascii
    $s11 = "function WtJW(ZkwlL) {" fullword ascii
    $s12 = "function jogQ(ErVHJ) {" fullword ascii
    $s13 = "if (sNlGo > 188180-373){return true;} else {return false;}" fullword ascii
    $s14 = "function CiUT(oeWbc) {" fullword ascii
    $s15 = "function RkfK(AAfuj,aOGDV) {" fullword ascii
    $s16 = "JOJ = W; break; " fullword ascii
    $s17 = "function RkawAgHx(bzAeC,BlNyuO) {" fullword ascii
    $s18 = "function sFtwRGIo(ZMA) {" fullword ascii
    $s19 = "function egrZ(PWPQi,IAXqv,iCIGY) {" fullword ascii
    $s20 = "return LDYSIsJ(ls,JEQak[851-845]+JEQak[149-142]+JEQak[400-392]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}