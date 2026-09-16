rule sig_20160404_86e6973e1b1b76e4d7f5bb202556606e {
  meta:
    description = "datamaliciousorder - file 20160404_86e6973e1b1b76e4d7f5bb202556606e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b087be388ba74c1128db2a173478efa14d24d1ac1e1492cb00a52ba40d067968"

  strings:
    $s1  = "var DU = true  , qsZd = PMX[7] + PMX[9] + PMX[11];" fullword ascii
    $s2  = "return VlBQBDE[0] + VlBQBDE[2] + VlBQBDE[4] + \".F\" + VlBQBDE[7] + VlBQBDE[9] + VlBQBDE[12] + VlBQBDE[14];" fullword ascii
    $s3  = "var PMX = (\"2.XMLHTTP EJrOfru kqlNI XML ream St jtDRIrse AD GjrQPku O CNTx D\").split(\" \");" fullword ascii
    $s4  = "var VlBQBDE = HWTgw(oHXwAfZkXe+\" \"+\"System nV gXAXe Obj gJIYTx ect aErKgCV CZuXH\", \" \");" fullword ascii
    $s5  = "GCBr.open(JqKNF,cLlaN,false);" fullword ascii
    $s6  = "if(X>=x.length) {break;}" fullword ascii
    $s7  = "function IypU(Tqwvf) {" fullword ascii
    $s8  = "if (bvgIZ == 626-426){return true;} else {return false;}" fullword ascii
    $s9  = "function cJMTwxjEC(beOkJ) {" fullword ascii
    $s10 = "function XRtRZhC(YzaI) {" fullword ascii
    $s11 = "return sbJEd.status;" fullword ascii
    $s12 = "return YBr.split(PdgtM);" fullword ascii
    $s13 = "var inNAohR = \"dghQYF*puq*pt.S\"+\"hell*eQOZYjE*Scri*\";" fullword ascii
    $s14 = "function VDjs(oqVkD) {" fullword ascii
    $s15 = "return RstYGzm(KE,JZizo[838-832]+JZizo[208-201]+JZizo[434-426]);" fullword ascii
    $s16 = "wEo = X; break; " fullword ascii
    $s17 = "function zZgT(ydiuW) {" fullword ascii
    $s18 = "return \"AdFCZnKVwMSDjc\";" fullword ascii
    $s19 = "return xhbiD;" fullword ascii
    $s20 = "function nseN(XeRPe,VeGXf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}