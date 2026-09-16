rule sig_20160321_95778783dff31c7a29a9d8a8065dc0f5 {
  meta:
    description = "datamaliciousorder - file 20160321_95778783dff31c7a29a9d8a8065dc0f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c22d9a80bd16033acc29c1bbaf3f8473abe15c1489e9a1980672b09ef7c5aaa"

  strings:
    $s1  = "return WScript.CreateObject(VMBJi);" fullword ascii
    $s2  = "return bUoifiC[0] + bUoifiC[2] + bUoifiC[4] + \".F\" + bUoifiC[7] + bUoifiC[9] + bUoifiC[12] + bUoifiC[14];" fullword ascii
    $s3  = "var WH = true  , GMsR = xpP[7] + xpP[9] + xpP[11];" fullword ascii
    $s4  = "var xpP = (\"2.XMLHTTP yDMdrfK TRCHi XML ream St mDgAJnPE AD Qttvlwn O RcOD D\").split(\" \");" fullword ascii
    $s5  = "var bUoifiC = qDOOM(tOgajYVYhn+\" \"+\"System hk idOAQ Obj OyBdpL ect QFUNgmC ANDvQ\", \" \");" fullword ascii
    $s6  = "KiXEX.open(oBWaf,bLZeN,false);" fullword ascii
    $s7  = "function pxeC(VMBJi) {" fullword ascii
    $s8  = "return CFyzd;" fullword ascii
    $s9  = "function afLZ(cndvp) {" fullword ascii
    $s10 = "function dzaJH(xxnICt) {" fullword ascii
    $s11 = "return QvLZLX.position=278-278;" fullword ascii
    $s12 = "function HPzB(WPnod) {" fullword ascii
    $s13 = "function CnDx(sRJpq,fxYbO) {" fullword ascii
    $s14 = "return QuM.split(PaESG);" fullword ascii
    $s15 = "if (moOWz == 1182-982){return true;} else {return false;}" fullword ascii
    $s16 = "function XyFj(KiXEX,bLZeN,oBWaf) {" fullword ascii
    $s17 = "return AZXR[aeHzWz[0]];" fullword ascii
    $s18 = "return new ActiveXObject(xxnICt);" fullword ascii
    $s19 = "function vEfa(ViCqM) {" fullword ascii
    $s20 = "function ajjJhNG(AZXR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}