rule sig_20151210_4ac6df1e0fcc3eba789192df9076c1c1 {
  meta:
    description = "datamaliciousorder - file 20151210_4ac6df1e0fcc3eba789192df9076c1c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0927a412fc486fd0d5f749834524c4517426d434ac895f73d651ef48b170c039"

  strings:
    $s1  = "function HEeYFrZ(xNDgRGUfAWPRnhqePkcCqnIbGWZQtFNjCQgD) {return !isNaN(parseFloat(xNDgRGUfAWPRnhqePkcCqnIbGWZQtFNjCQgD)) && isFin" ascii
    $s2  = "function HEeYFrZ(xNDgRGUfAWPRnhqePkcCqnIbGWZQtFNjCQgD) {return !isNaN(parseFloat(xNDgRGUfAWPRnhqePkcCqnIbGWZQtFNjCQgD)) && isFin" ascii
    $s3  = "function kUbYndWDDMOkmbvLt(yRCyT){mzNzfJqxcHR= '';for(yBpjsFIVEls=(-963+963)/217; yBpjsFIVEls < (1447+517)/982; yBpjsFIVEls++) {" ascii
    $s4  = "function zqyoU(hEDPaLdcmkW,qxDgiUrdvRgPl,ZNHxoTyA){qtjV=parseInt(hEDPaLdcmkW,qxDgiUrdvRgPl);Xyger=qtjV.toString(ZNHxoTyA);return" ascii
    $s5  = "function kUbYndWDDMOkmbvLt(yRCyT){mzNzfJqxcHR= '';for(yBpjsFIVEls=(-963+963)/217; yBpjsFIVEls < (1447+517)/982; yBpjsFIVEls++) {" ascii
    $s6  = "]++;}} return mzNzfJqxcHR}" fullword ascii
    $s7  = "function jNYUoFxiSutPzcIMiCwyOXobwDltKSCZjoWiDbZYnLLHAsyOjyQOYE(QvtCNscUdtBTD,VFcwpWjJoHTAcQ){ return vfcTHezBiLhiE[zqyoU(QvtCNs" ascii
    $s8  = " Xyger;}function BLlrFrdolexYjDx(KKzWssHVCoXMBLsAk){eval(KKzWssHVCoXMBLsAk)}" fullword ascii
    $s9  = "lxksHqgpo[yBpjsFIVEls]=(-629+629)/819; while(true) { if(lxksHqgpo[yBpjsFIVEls] > yRCyT[yBpjsFIVEls].length-(161+650)/811) { brea" ascii
    $s10 = "function jNYUoFxiSutPzcIMiCwyOXobwDltKSCZjoWiDbZYnLLHAsyOjyQOYE(QvtCNscUdtBTD,VFcwpWjJoHTAcQ){ return vfcTHezBiLhiE[zqyoU(QvtCNs" ascii
    $s11 = "function xJxBPAHjtkR(eoxHnNKi,BdvcRp){return eoxHnNKi.split(BdvcRp)}" fullword ascii
    $s12 = "function zqyoU(hEDPaLdcmkW,qxDgiUrdvRgPl,ZNHxoTyA){qtjV=parseInt(hEDPaLdcmkW,qxDgiUrdvRgPl);Xyger=qtjV.toString(ZNHxoTyA);return" ascii
    $s13 = "zQFytlx=(-626+626)/780;while(true){if(zQFytlx>=(97013+395)/761){break;}vfcTHezBiLhiE[zQFytlx]=String.fromCharCode(zQFytlx);zQFyt" ascii
    $s14 = "zQFytlx=(-626+626)/780;while(true){if(zQFytlx>=(97013+395)/761){break;}vfcTHezBiLhiE[zQFytlx]=String.fromCharCode(zQFytlx);zQFyt" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}