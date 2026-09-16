rule sig_20151210_d4256ea1515f3ebaeeded81a19591904 {
  meta:
    description = "datamaliciousorder - file 20151210_d4256ea1515f3ebaeeded81a19591904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617bf2f72fa7dce18b247fa401476dcdaf9b6cbf44efffd9d5bca7ab8ff77b74"

  strings:
    $s1  = "function VRLZsJS(iOOQZNezGlLpeuosiYvRrMWrlxYDyfULkRxT) {return !isNaN(parseFloat(iOOQZNezGlLpeuosiYvRrMWrlxYDyfULkRxT)) && isFin" ascii
    $s2  = "function VRLZsJS(iOOQZNezGlLpeuosiYvRrMWrlxYDyfULkRxT) {return !isNaN(parseFloat(iOOQZNezGlLpeuosiYvRrMWrlxYDyfULkRxT)) && isFin" ascii
    $s3  = "function CqKWqkIiNOMVQinqZVPvIVBiZxZsdxbARkpiLWfxLkEfjMRgEakdzq(ApYTUuasOEHxe,VwNxrrKcrDdKEu){ return SLKTLvlQfQFFE[MCObW(ApYTUu" ascii
    $s4  = "]++;}} return ZLuQTKZDCBH}" fullword ascii
    $s5  = "function jZucpWpMoiAoFAUoL(PsWqM){ZLuQTKZDCBH= '';for(UZzHfjxUSii=(-824+824)/171; UZzHfjxUSii < (-456+558)/51; UZzHfjxUSii++) {S" ascii
    $s6  = "NYMFhwsW[UZzHfjxUSii]=(-195+195)/238; while(true) { if(SNYMFhwsW[UZzHfjxUSii] > PsWqM[UZzHfjxUSii].length-(-239+671)/432) { brea" ascii
    $s7  = "function jZucpWpMoiAoFAUoL(PsWqM){ZLuQTKZDCBH= '';for(UZzHfjxUSii=(-824+824)/171; UZzHfjxUSii < (-456+558)/51; UZzHfjxUSii++) {S" ascii
    $s8  = "function CqKWqkIiNOMVQinqZVPvIVBiZxZsdxbARkpiLWfxLkEfjMRgEakdzq(ApYTUuasOEHxe,VwNxrrKcrDdKEu){ return SLKTLvlQfQFFE[MCObW(ApYTUu" ascii
    $s9  = "function MCObW(hFXdYfBSPwz,CYyPWEopZjkfW,UDlPqPhy){TWaX=parseInt(hFXdYfBSPwz,CYyPWEopZjkfW);EXCse=TWaX.toString(UDlPqPhy);return" ascii
    $s10 = "function MCObW(hFXdYfBSPwz,CYyPWEopZjkfW,UDlPqPhy){TWaX=parseInt(hFXdYfBSPwz,CYyPWEopZjkfW);EXCse=TWaX.toString(UDlPqPhy);return" ascii
    $s11 = "function NetqJYHIciB(SLagUZpl,eyILVg){return SLagUZpl.split(eyILVg)}" fullword ascii
    $s12 = " EXCse;}function pouQAElnVzjULZA(WetrUEIZsfCnJHkmu){eval(WetrUEIZsfCnJHkmu)}" fullword ascii
    $s13 = "qRRfbap=(-663+663)/901;while(true){if(qRRfbap>=(52996+252)/416){break;}SLKTLvlQfQFFE[qRRfbap]=String.fromCharCode(qRRfbap);qRRfb" ascii
    $s14 = "qRRfbap=(-663+663)/901;while(true){if(qRRfbap>=(52996+252)/416){break;}SLKTLvlQfQFFE[qRRfbap]=String.fromCharCode(qRRfbap);qRRfb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}