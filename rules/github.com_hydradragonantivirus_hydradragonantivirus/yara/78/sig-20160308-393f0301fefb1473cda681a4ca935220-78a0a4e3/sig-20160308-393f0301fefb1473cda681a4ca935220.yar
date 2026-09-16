rule sig_20160308_393f0301fefb1473cda681a4ca935220 {
  meta:
    description = "datamaliciousorder - file 20160308_393f0301fefb1473cda681a4ca935220.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eb66007594006fb9b038ecaded24261e63201215194a203490cf78067021bea"

  strings:
    $s1  = "return dJlIbQw[0] + dJlIbQw[2] + dJlIbQw[4] + \".F\" + dJlIbQw[7] + dJlIbQw[9] + dJlIbQw[12] + dJlIbQw[14];" fullword ascii
    $s2  = "var VQ = true  , lpLs = lRG[7] + lRG[9] + lRG[11];" fullword ascii
    $s3  = "var dJlIbQw = \"Sc Nuvhtyk r jgZdtFqRu ipting yVvBNDt BTt ile RDBmtpWyfXniYt System oV pNFOE Obj kHOzSV ect atGyATn\".split(\" " ascii
    $s4  = "efGXN.open(Tgbvo,ReFUk,false);" fullword ascii
    $s5  = "return lNCZSHK" fullword ascii
    $s6  = "function qcEGi(ppJYEA) {" fullword ascii
    $s7  = "return new ActiveXObject(ppJYEA);" fullword ascii
    $s8  = "if (yiDvV > 187054-425){return true;} else {return false;}" fullword ascii
    $s9  = "return BxqOD;" fullword ascii
    $s10 = "function xfUm(YuNCO) {" fullword ascii
    $s11 = "if (V >= rwhpI.length) {break;}" fullword ascii
    $s12 = "function srFq(DyBim) {" fullword ascii
    $s13 = "function FXpa(tfSIO) {" fullword ascii
    $s14 = "function RvzMLSPI(hvg) {" fullword ascii
    $s15 = "return hvg.size;" fullword ascii
    $s16 = "return iO.ExpandEnvironmentStrings(FXAcr[6]+FXAcr[7]+FXAcr[8]);" fullword ascii
    $s17 = "if (((new Date())>0,7651551888)) {" fullword ascii
    $s18 = "if (DyBim == 554-354){return true;} else {return false;}" fullword ascii
    $s19 = "function mSwnTIeXX(qZIsx,aflcx,XsMzi,mNoY) {" fullword ascii
    $s20 = "function wjPq(efGXN,ReFUk,Tgbvo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}