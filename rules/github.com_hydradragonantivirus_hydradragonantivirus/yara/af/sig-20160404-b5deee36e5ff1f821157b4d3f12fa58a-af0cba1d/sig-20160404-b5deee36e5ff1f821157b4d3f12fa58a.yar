rule sig_20160404_b5deee36e5ff1f821157b4d3f12fa58a {
  meta:
    description = "datamaliciousorder - file 20160404_b5deee36e5ff1f821157b4d3f12fa58a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34f66ebadbc4afb27162f8e180eb239819c13c869fd34b352e3f0b6e3889c9e4"

  strings:
    $s1  = "return DIxBkqN[0] + DIxBkqN[2] + DIxBkqN[4] + \".F\" + DIxBkqN[7] + DIxBkqN[9] + DIxBkqN[12] + DIxBkqN[14];" fullword ascii
    $s2  = "var AV = true  , SXwx = GRD[7] + GRD[9] + GRD[11];" fullword ascii
    $s3  = "var DIxBkqN = brALf(kAqjLkzlra+\" \"+\"System eu vakhY Obj DgrVvh ect TqkfCKD xLqYc\", \" \");" fullword ascii
    $s4  = "var GRD = (\"2.XMLHTTP gbXkptG eIOyZ XML ream St TytUAojU AD LopwPET O XvFQ D\").split(\" \");" fullword ascii
    $s5  = "UJVw.open(wxWCZ,owsOy,false);" fullword ascii
    $s6  = "if(F>=T.length) {break;}" fullword ascii
    $s7  = "function HqtwOxQnH(OJybBWsOsJj) {" fullword ascii
    $s8  = "function IWgMhvnd(neTS) {" fullword ascii
    $s9  = "function poQm(PtoRl) {" fullword ascii
    $s10 = "if (A >= iwhfI.length) {break;}" fullword ascii
    $s11 = "return ZdzHYcf(Tm,iWGvt[689-683]+iWGvt[899-892]+iWGvt[585-577]);" fullword ascii
    $s12 = "return YDpSr;" fullword ascii
    $s13 = "return nPd.size;" fullword ascii
    $s14 = "function oJNI(bNnRn) {" fullword ascii
    $s15 = "function Tqbs(YMRZQ,yBARZ) {" fullword ascii
    $s16 = "return aHUC[izJSLQ[0]];" fullword ascii
    $s17 = "function RPFnvcZwf(uuXBw) {" fullword ascii
    $s18 = "function Wdgu(pVqdj) {" fullword ascii
    $s19 = "function qdLh(NHZKB) {" fullword ascii
    $s20 = "function brALf(NFV,iXeth) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}