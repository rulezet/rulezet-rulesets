rule sig_20160311_967cb9a3096d0c3fc7faf269e0062c61 {
  meta:
    description = "datamaliciousorder - file 20160311_967cb9a3096d0c3fc7faf269e0062c61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9287e8077fdb099c981b4bbee715e3de514a35250b23f8af0b624a9dbb91899"

  strings:
    $s1  = "var yF = true  , ChYT = dPe[7] + dPe[9] + dPe[11];" fullword ascii
    $s2  = "return lRndkiI[0] + lRndkiI[2] + lRndkiI[4] + \".F\" + lRndkiI[7] + lRndkiI[9] + lRndkiI[12] + lRndkiI[14];" fullword ascii
    $s3  = "var dPe = (\"2.XMLHTTP irBhqDW TVGBG XML ream St qKEPkABZ AD HXxJsPb O GvuN D\").split(\" \");" fullword ascii
    $s4  = "var lRndkiI = \"Sc Eorgyey r IkmIdwmLw ipting PSNxnmF JpK ile XELaakbPhqYPJU System fs ahphX Obj uEBtyE ect zkRcrGT\".split(\" " ascii
    $s5  = "MILtr.open(ZmfDd,pAXJU,false);" fullword ascii
    $s6  = "function XZof(hrQrR) {" fullword ascii
    $s7  = "function GvwhqiUs(nCI) {" fullword ascii
    $s8  = "if(H>=h.length) {break;}" fullword ascii
    $s9  = "return PCZF.ExpandEnvironmentStrings(lQDxT);" fullword ascii
    $s10 = "function wvjm(LBrPt,xmWdK) {" fullword ascii
    $s11 = "return bKWnAPo" fullword ascii
    $s12 = "function oLcyFEqZ() {" fullword ascii
    $s13 = "function JlzBixZ(yqBB) {" fullword ascii
    $s14 = "return new ActiveXObject(dcTAJU);" fullword ascii
    $s15 = "return nCI.size;" fullword ascii
    $s16 = "function lzKK(rnrjs) {" fullword ascii
    $s17 = "function Jlukt(RsrYsH) {" fullword ascii
    $s18 = "function CUVhyrd(PCZF,lQDxT) {" fullword ascii
    $s19 = "Gqe = H; break; " fullword ascii
    $s20 = "return BmsVN;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}