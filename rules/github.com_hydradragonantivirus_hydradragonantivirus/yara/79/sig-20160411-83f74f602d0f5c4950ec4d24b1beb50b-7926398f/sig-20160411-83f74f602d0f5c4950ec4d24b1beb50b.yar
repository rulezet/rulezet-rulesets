rule sig_20160411_83f74f602d0f5c4950ec4d24b1beb50b {
  meta:
    description = "datamaliciousorder - file 20160411_83f74f602d0f5c4950ec4d24b1beb50b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3ef12915563846f4a5ea0d3b928bcd6a41e829f6eb0585b904c17a47f8fffa3"

  strings:
    $s1  = "var ou = true  , bpaL = ZbZ[7] + ZbZ[9] + ZbZ[11];" fullword ascii
    $s2  = "return dMskUSz[0] + dMskUSz[2] + dMskUSz[4] + \".F\" + dMskUSz[7] + dMskUSz[9] + dMskUSz[12] + dMskUSz[14];" fullword ascii
    $s3  = "var ZbZ = (\"2.XMLHTTP DoCWnRY bRQpZ XML ream St DngDeyKQ AD yYzWPOo O CFyd D\").split(\" \");" fullword ascii
    $s4  = "QjVj.open(DwOlw,jtfSF,false);" fullword ascii
    $s5  = "function vZdZ(HoSzw) {" fullword ascii
    $s6  = "function nWoXHw(ecZmnmH) {" fullword ascii
    $s7  = "function ysLl(tXzHM) {" fullword ascii
    $s8  = "if (OMbWC > 167827-544){return true;} else {return false;}" fullword ascii
    $s9  = "function MIHVUUCB(MtTU) {" fullword ascii
    $s10 = "if (tXzHM == 797-597){return true;} else {return false;}" fullword ascii
    $s11 = "function RRHiqxKpd(XBtTlnTpiMf) {" fullword ascii
    $s12 = "function nOeL(gHoZX) {" fullword ascii
    $s13 = "function IEvZYBnNJ(EHjSg) {" fullword ascii
    $s14 = "function ZRXfyopL(cIL) {" fullword ascii
    $s15 = "return new ActiveXObject(GfOj);" fullword ascii
    $s16 = "return twVUgW[ehgp[789-789]]=286-286;" fullword ascii
    $s17 = "return OEAb[zHIGCyQ[0]+zHIGCyQ[1]];" fullword ascii
    $s18 = "if (r >= HoSzw.length) {break;}" fullword ascii
    $s19 = "return lCF[Tlze[0]](MSyAL);" fullword ascii
    $s20 = "function bWXo(VgFYq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}