rule sig_20160310_7dd57ef5ceba8dcfc37aac2061d1f2cb {
  meta:
    description = "datamaliciousorder - file 20160310_7dd57ef5ceba8dcfc37aac2061d1f2cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92913e51ee0e25242b39e50d561e5525fad4ee1feffe5cb873bf7475d3c23cc3"

  strings:
    $s1  = "return mDZKzvm[0] + mDZKzvm[2] + mDZKzvm[4] + \".F\" + mDZKzvm[7] + mDZKzvm[9] + mDZKzvm[12] + mDZKzvm[14];" fullword ascii
    $s2  = "var VZ = true  , ZEDk = ztF[7] + ztF[9] + ztF[11];" fullword ascii
    $s3  = "gMjMq.open(fESrf,lUCTx,false);" fullword ascii
    $s4  = "var mDZKzvm = \"Sc xrhYlhj r JEQDqkqZB ipting RdCqBbz Yqm ile VeWlDgwOATgVGI System He PmKKP Obj fqYGLZ ect dqXJLhc\".split(\" " ascii
    $s5  = "var ztF = (\"2.XMLHTTP czYJVje gBOdk XML ream St Wpqcyckk AD RvOsibB O Buuu D\").split(\" \");" fullword ascii
    $s6  = "function vuFmx(aMblyI) {" fullword ascii
    $s7  = "return NAtH.responseBody;" fullword ascii
    $s8  = "function UEXBAULV(hNjgf,LUGpIb) {" fullword ascii
    $s9  = "function IMfv(rWKIY,RkBHL) {" fullword ascii
    $s10 = "function FRAACEH(NAtH) {" fullword ascii
    $s11 = "function ktVvokme() {" fullword ascii
    $s12 = "function awjg(bNfyA) {" fullword ascii
    $s13 = "function LZraNNM(fzeV,EYPmY) {" fullword ascii
    $s14 = "function BDeW(EjhBD) {" fullword ascii
    $s15 = "if (uEfJB == 523-323){return true;} else {return false;}" fullword ascii
    $s16 = "return fzeV.ExpandEnvironmentStrings(EYPmY);" fullword ascii
    $s17 = "function fKUjbTer(YZl) {" fullword ascii
    $s18 = "function oqUJ(uEfJB) {" fullword ascii
    $s19 = "function GtdB(VHKFX) {" fullword ascii
    $s20 = "function Lnls(VahUl,LMEBt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}