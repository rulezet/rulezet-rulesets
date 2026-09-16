rule sig_20160302_b68a90b6bc86475470fc5918f2ca0c45 {
  meta:
    description = "datamaliciousorder - file 20160302_b68a90b6bc86475470fc5918f2ca0c45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deeb3d582a1cfe95d3a99d4ac8ad5957178a1d6a25e4a7c7597439d3b4309220"

  strings:
    $s1  = "var oq = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(nKxYs);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + DWalNCK + \".F\" + gllQAvTXbJ + rXGUh + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var Sg = true  , FmMK = rVw[7] + \"\" + rVw[9];" fullword ascii
    $s5  = "var rVw = (mgB + \"TTP\" + \" aIUBGWW pglKQ XML ream St QhvOgKNC AD UzRCubZ OD\").split(\" \");" fullword ascii
    $s6  = "JZVot.open(CFivc,lzXkS,false);" fullword ascii
    $s7  = "function TVIm(ecGgH) {" fullword ascii
    $s8  = "function cRcU(MhpFe) {" fullword ascii
    $s9  = "return new ActiveXObject(Pvhuph);" fullword ascii
    $s10 = "return xi.ExpandEnvironmentStrings(oq);" fullword ascii
    $s11 = "function IXqwXMQvu(jRAsJ,ctfhZ,tPmOU) {" fullword ascii
    $s12 = "if(x>=N.length) {break;}" fullword ascii
    $s13 = "function ZpSG(HPOaK,jtATh) {" fullword ascii
    $s14 = "function CIcNfQtA() {" fullword ascii
    $s15 = "function oSbT(GYszU) {" fullword ascii
    $s16 = "function EJoznTtYW(ouJqmtyuBkS) {" fullword ascii
    $s17 = "function AGMy(QEtFa) {" fullword ascii
    $s18 = "if (((new Date())>0,7265220888)) {" fullword ascii
    $s19 = "if (ecGgH == 1099-899){return true;} else {return false;}" fullword ascii
    $s20 = "function vjrcW(Pvhuph) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}