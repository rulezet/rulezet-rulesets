rule sig_20160321_dd58547703566b9d9af7ba0a970e93de {
  meta:
    description = "datamaliciousorder - file 20160321_dd58547703566b9d9af7ba0a970e93de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2712790cc92daef3bdf88891909f4c430e71ad45f2ca1a612a4f8ce4c86f0d94"

  strings:
    $s1  = "return WScript.CreateObject(cHceh);" fullword ascii
    $s2  = "return mZtSDAs[0] + mZtSDAs[2] + mZtSDAs[4] + \".F\" + mZtSDAs[7] + mZtSDAs[9] + mZtSDAs[12] + mZtSDAs[14];" fullword ascii
    $s3  = "var XC = true  , FSxF = ihY[7] + ihY[9] + ihY[11];" fullword ascii
    $s4  = "DCKsi.open(IQXTF,MEXBo,false);" fullword ascii
    $s5  = "var mZtSDAs = vMPBZ(xXCmShXYEm+\" \"+\"System Ct FohDJ Obj uaEIqz ect SGxcpqt Yqbtu\", \" \");" fullword ascii
    $s6  = "var ihY = (\"2.XMLHTTP WqwVWng yMmJm XML ream St iAQqJadt AD dGRxGyi O dHJK D\").split(\" \");" fullword ascii
    $s7  = "return AIKSY.status;" fullword ascii
    $s8  = "function YLWO(MPhbv,jvSFl) {" fullword ascii
    $s9  = "return qzW.split(WVBgW);" fullword ascii
    $s10 = "return Xvro[OdduXQ[0]];" fullword ascii
    $s11 = "function wVUm(cHceh) {" fullword ascii
    $s12 = "function ltSn(nfopa) {" fullword ascii
    $s13 = "function haAzi(Hlwogu) {" fullword ascii
    $s14 = "function vMPBZ(qzW,WVBgW) {" fullword ascii
    $s15 = "function TRJf(eDJEf) {" fullword ascii
    $s16 = "if (v >= nBjXW.length) {break;}" fullword ascii
    $s17 = "if (BhqSt > 188710-355){return true;} else {return false;}" fullword ascii
    $s18 = "return new ActiveXObject(SsPDCw);" fullword ascii
    $s19 = "function OhYi(vojxf) {" fullword ascii
    $s20 = "return BfbVdgV(pG,rtoZv[118-112]+rtoZv[188-181]+rtoZv[924-916]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}