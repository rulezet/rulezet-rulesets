rule sig_20160405_0798e6ecfac284d7d3d68dc34e0e08e6 {
  meta:
    description = "datamaliciousorder - file 20160405_0798e6ecfac284d7d3d68dc34e0e08e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33e49a50c140430b5e83604adc3304b1863ee4b6f7764eb75cff89066cbe66d"

  strings:
    $s1  = "var ih = true  , TxGh = hZi[7] + hZi[9] + hZi[11];" fullword ascii
    $s2  = "return QqjJOrT[0] + QqjJOrT[2] + QqjJOrT[4] + \".F\" + QqjJOrT[7] + QqjJOrT[9] + QqjJOrT[12] + QqjJOrT[14];" fullword ascii
    $s3  = "var hZi = (\"2.XMLHTTP XNxxtOW lOjsy XML ream St rjBXGgLp AD arWghcD O swUL D\").split(\" \");" fullword ascii
    $s4  = "kYni.open(yXGYk,vwUBu,false);" fullword ascii
    $s5  = "if (o >= uCOXN.length) {break;}" fullword ascii
    $s6  = "function YSfzYhzpw(CESZQ) {" fullword ascii
    $s7  = "hHEd(dL,YanRs+X[r]+U, FsL[12]+FsL[14]+FsL[16]); puck(dL); " fullword ascii
    $s8  = "if(r>=X.length) {break;}" fullword ascii
    $s9  = "function JgvC(LXtBZ,vnpkK) {" fullword ascii
    $s10 = "return seXkskj[0];" fullword ascii
    $s11 = "return QnVgcUb;" fullword ascii
    $s12 = "function puck(fGYVN) {" fullword ascii
    $s13 = "if (zXiVK == 638-438){return true;} else {return false;}" fullword ascii
    $s14 = "if (ZocpX > 163023-157){return true;} else {return false;}" fullword ascii
    $s15 = "function ImkorhLS(KsRy) {" fullword ascii
    $s16 = "function ZgHQo(WDhHFt) {" fullword ascii
    $s17 = "function EFcG(zXiVK) {" fullword ascii
    $s18 = "return xqmg;" fullword ascii
    $s19 = "function Lvyhmcj(aHzY,xcmfw) {" fullword ascii
    $s20 = "function BUerzB(xzNeAbE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}