rule sig_20160314_e73fcc269decaaa53857fa1c4a7e5844 {
  meta:
    description = "datamaliciousorder - file 20160314_e73fcc269decaaa53857fa1c4a7e5844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c36a6cf08bfcb09e2ec7405c0b664c0ce8243347759379050498ee35c64cf43c"

  strings:
    $s1  = "return NYDqqsj[0] + NYDqqsj[2] + NYDqqsj[4] + \".F\" + NYDqqsj[7] + NYDqqsj[9] + NYDqqsj[12] + NYDqqsj[14];" fullword ascii
    $s2  = "var Bv = true  , NLyR = XsQ[7] + XsQ[9] + XsQ[11];" fullword ascii
    $s3  = "CBXUK.open(riXiN,VhefJ,false);" fullword ascii
    $s4  = "var XsQ = (\"2.XMLHTTP tZSkSWD xKJJb XML ream St hxJPKwZN AD qHrQsjE O CgIZ D\").split(\" \");" fullword ascii
    $s5  = "return SoSN.responseBody;" fullword ascii
    $s6  = "return rEY.size;" fullword ascii
    $s7  = "function bcbXw(jcmwQj) {" fullword ascii
    $s8  = "return IippY;" fullword ascii
    $s9  = "function vDNwDEYV() {" fullword ascii
    $s10 = "return xkgCquV" fullword ascii
    $s11 = "function TeCOrrwcu(xhwnkkNLqfH) {" fullword ascii
    $s12 = "function zeQVS(mluHGM) {" fullword ascii
    $s13 = "if (XGWLB == 891-691){return true;} else {return false;}" fullword ascii
    $s14 = "function hhtz(BhcHD) {" fullword ascii
    $s15 = "function gOyl(EOQTt,Axxqa) {" fullword ascii
    $s16 = "function JrZqIDI(SoSN) {" fullword ascii
    $s17 = "function bvWL(CBXUK,VhefJ,riXiN) {" fullword ascii
    $s18 = "function UzjQvIYkI() {" fullword ascii
    $s19 = "return XECuXEI(kU,Anafk[684-678]+Anafk[674-667]+Anafk[976-968]);" fullword ascii
    $s20 = "return new ActiveXObject(jcmwQj);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}