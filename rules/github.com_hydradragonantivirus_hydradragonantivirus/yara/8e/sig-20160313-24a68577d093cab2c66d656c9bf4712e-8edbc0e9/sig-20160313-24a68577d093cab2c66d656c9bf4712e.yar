rule sig_20160313_24a68577d093cab2c66d656c9bf4712e {
  meta:
    description = "datamaliciousorder - file 20160313_24a68577d093cab2c66d656c9bf4712e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fd6115745b0c13e9f1ea40a583b1210fd8a52b36ad7ec377ab314cdb7165a64"

  strings:
    $s1  = "var Nn = true  , oroA = agh[7] + agh[9] + agh[11];" fullword ascii
    $s2  = "return WTnAGOc[0] + WTnAGOc[2] + WTnAGOc[4] + \".F\" + WTnAGOc[7] + WTnAGOc[9] + WTnAGOc[12] + WTnAGOc[14];" fullword ascii
    $s3  = "kpQGY.open(kdKER,pUYTr,false);" fullword ascii
    $s4  = "var WTnAGOc = \"Sc yvPmWTc r fXDkGwQzV ipting iSpgmNB ToO ile wxROWxCWhPnEpM System WH AZUUT Obj fkiqJB ect uuAQDJU\".split(\" " ascii
    $s5  = "var agh = (\"2.XMLHTTP qzDCBTW KxgNh XML ream St DyuYRSjl AD kUvRKha O rNYA D\").split(\" \");" fullword ascii
    $s6  = "return zFJPbX.position=276-276;" fullword ascii
    $s7  = "function ocBbA(zFJPbX) {" fullword ascii
    $s8  = "function nYHl(tNWWr,LbNfs) {" fullword ascii
    $s9  = "function nAQD(gSqdy) {" fullword ascii
    $s10 = "function HhnylSF(XgxT) {" fullword ascii
    $s11 = "function QGEacYxE() {" fullword ascii
    $s12 = "function QylH(oCqKS) {" fullword ascii
    $s13 = "function uoiU(kpQGY,pUYTr,kdKER) {" fullword ascii
    $s14 = "return vZWEc.status;" fullword ascii
    $s15 = "function KoJPjBpUU(UiecsdaAasB) {" fullword ascii
    $s16 = "function batX(XmuCO) {" fullword ascii
    $s17 = "return XgxT.responseBody;" fullword ascii
    $s18 = "function JAXP(GaGgp) {" fullword ascii
    $s19 = "MfP = M; break; " fullword ascii
    $s20 = "return new ActiveXObject(fSzViG);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}