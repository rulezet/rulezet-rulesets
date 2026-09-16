rule sig_20160321_f905d3a6fb1e2f9692aa272cd3ffcc07 {
  meta:
    description = "datamaliciousorder - file 20160321_f905d3a6fb1e2f9692aa272cd3ffcc07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c237a7525f86b52894598ede4b388c27f21719632c44fa57f2b79d6103116484"

  strings:
    $s1  = "return WScript.CreateObject(MkdBo);" fullword ascii
    $s2  = "return zyBWGAH[0] + zyBWGAH[2] + zyBWGAH[4] + \".F\" + zyBWGAH[7] + zyBWGAH[9] + zyBWGAH[12] + zyBWGAH[14];" fullword ascii
    $s3  = "var sB = true  , rfsb = OZi[7] + OZi[9] + OZi[11];" fullword ascii
    $s4  = "var OZi = (\"2.XMLHTTP SpTdypb YfTkA XML ream St IATjqjkD AD VeNWKMM O oTwc D\").split(\" \");" fullword ascii
    $s5  = "var zyBWGAH = RFNkH(uQoMvQRnOS+\" \"+\"System MF ItrBt Obj rfYaXm ect tGFculQ pRyOO\", \" \");" fullword ascii
    $s6  = "vNGUV.open(iuGij,vRsib,false);" fullword ascii
    $s7  = "if(T>=i.length) {break;}" fullword ascii
    $s8  = "return dxA.size;" fullword ascii
    $s9  = "function zJnL(ICfoj) {" fullword ascii
    $s10 = "function yEgy(ZfjFk) {" fullword ascii
    $s11 = "function HQrwLrJ(uHkE,aoAim) {" fullword ascii
    $s12 = "function kucJGOj(SCHg) {" fullword ascii
    $s13 = "if (LbxHN == 659-459){return true;} else {return false;}" fullword ascii
    $s14 = "return waDnm.status;" fullword ascii
    $s15 = "if (E >= ZfjFk.length) {break;}" fullword ascii
    $s16 = "function WDToYPjC(dxA) {" fullword ascii
    $s17 = "function tbRrN(fxItDJ) {" fullword ascii
    $s18 = "function ulVg(MkdBo) {" fullword ascii
    $s19 = "return dpljc;" fullword ascii
    $s20 = "function PyNU(zrzAL,QeUnn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}