rule sig_20160309_dcf3b5da56cd62b31f80b0fc46a4ab28 {
  meta:
    description = "datamaliciousorder - file 20160309_dcf3b5da56cd62b31f80b0fc46a4ab28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a079c430c49231bdf6de9a6acd4c51614b7d7c596229b0ac05f086dbbcb85baa"

  strings:
    $s1  = "var db = true  , LlFi = hxT[7] + hxT[9] + hxT[11];" fullword ascii
    $s2  = "return aXqyvni[0] + aXqyvni[2] + aXqyvni[4] + \".F\" + aXqyvni[7] + aXqyvni[9] + aXqyvni[12] + aXqyvni[14];" fullword ascii
    $s3  = "var hxT = (\"2.XMLHTTP KoNfEpo agjjk XML ream St rrKitymD AD AKsGXAS O xRow D\").split(\" \");" fullword ascii
    $s4  = "JssZA.open(wFIvO,YqpZG,false);" fullword ascii
    $s5  = "var aXqyvni = \"Sc fhaqvvV r FLWwIXhgZ ipting VfFEoqw rFk ile GLfudtthfaHrjf System NZ UiDSD Obj ROtDCg ect cpeIItQ\".split(\" " ascii
    $s6  = "return zJKyF.status;" fullword ascii
    $s7  = "if (YMENk > 171204-431){return true;} else {return false;}" fullword ascii
    $s8  = "function zQvxWaEH() {" fullword ascii
    $s9  = "return SgK.size;" fullword ascii
    $s10 = "function KZklPTC(ABaA) {" fullword ascii
    $s11 = "function nKWi(MwMnj) {" fullword ascii
    $s12 = "function pnhh(JssZA,YqpZG,wFIvO) {" fullword ascii
    $s13 = "return new ActiveXObject(qooWMv);" fullword ascii
    $s14 = "function gzDcjtN(gRCr,eylxc) {" fullword ascii
    $s15 = "function IYYgkdJd(SgK) {" fullword ascii
    $s16 = "return gzDcjtN(eI,iuXZU[510-504]+iuXZU[1003-996]+iuXZU[449-441]);" fullword ascii
    $s17 = "function DNglM(qooWMv) {" fullword ascii
    $s18 = "function bwLVYoVC(bSMfk,gNirhA) {" fullword ascii
    $s19 = "function GSur(zJKyF) {" fullword ascii
    $s20 = "if(g>=I.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}