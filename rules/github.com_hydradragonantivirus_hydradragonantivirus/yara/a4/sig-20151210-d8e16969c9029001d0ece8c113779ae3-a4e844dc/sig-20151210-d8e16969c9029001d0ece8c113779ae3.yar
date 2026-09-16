rule sig_20151210_d8e16969c9029001d0ece8c113779ae3 {
  meta:
    description = "datamaliciousorder - file 20151210_d8e16969c9029001d0ece8c113779ae3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "663ded5060017e699740494dbfc1f76a984e4091c2711c94ce604fcecb94d6a5"

  strings:
    $s1  = "function DpCgb(mXoJNqYUZDf,WLdOCBKOcjsFn,tgEtAyWH){RGNb=parseInt(mXoJNqYUZDf,WLdOCBKOcjsFn);fmyNX=RGNb.toString(tgEtAyWH);return" ascii
    $s2  = "function DpCgb(mXoJNqYUZDf,WLdOCBKOcjsFn,tgEtAyWH){RGNb=parseInt(mXoJNqYUZDf,WLdOCBKOcjsFn);fmyNX=RGNb.toString(tgEtAyWH);return" ascii
    $s3  = "function igcxofmnWkjxDwZHq(CFRrx){gzWsTVFlQQU= '';for(eLaIJBUYCrj=(-498+498)/884; eLaIJBUYCrj < (254+22)/138; eLaIJBUYCrj++) {rg" ascii
    $s4  = "function FnsQZygcrXfkHukTMZBZtjmsRehmIONVcKrwrdRgMOPUOMXClUKptx(jwfOWCNuxXEmq,DXcUnezkTweHOh){ return UdxLkRXyPOsMm[DpCgb(jwfOWC" ascii
    $s5  = "function FnsQZygcrXfkHukTMZBZtjmsRehmIONVcKrwrdRgMOPUOMXClUKptx(jwfOWCNuxXEmq,DXcUnezkTweHOh){ return UdxLkRXyPOsMm[DpCgb(jwfOWC" ascii
    $s6  = "function LCWVoCyICxF(jmAXTaNu,raOKHe){return jmAXTaNu.split(raOKHe)}" fullword ascii
    $s7  = " fmyNX;}function KqvRvWmIDFWGpzP(XyNJhitczRAcHDGSy){eval(XyNJhitczRAcHDGSy)}" fullword ascii
    $s8  = "OgoWZtS=(-1+1)/466;while(true){if(OgoWZtS>=(22383+401)/178){break;}UdxLkRXyPOsMm[OgoWZtS]=String.fromCharCode(OgoWZtS);OgoWZtS++" ascii
    $s9  = "OgoWZtS=(-1+1)/466;while(true){if(OgoWZtS>=(22383+401)/178){break;}UdxLkRXyPOsMm[OgoWZtS]=String.fromCharCode(OgoWZtS);OgoWZtS++" ascii
    $s10 = "function igcxofmnWkjxDwZHq(CFRrx){gzWsTVFlQQU= '';for(eLaIJBUYCrj=(-498+498)/884; eLaIJBUYCrj < (254+22)/138; eLaIJBUYCrj++) {rg" ascii
    $s11 = "GGiHfbA[eLaIJBUYCrj]=(-32+32)/550; while(true) { if(rgGGiHfbA[eLaIJBUYCrj] > CFRrx[eLaIJBUYCrj].length-(231+561)/792) { break; }" ascii
    $s12 = "function cgnceLR(wzioivFbOcJjimtJvameHaeKBjLWWrXRvMCA) {return !isNaN(parseFloat(wzioivFbOcJjimtJvameHaeKBjLWWrXRvMCA)) && isFin" ascii
    $s13 = "function cgnceLR(wzioivFbOcJjimtJvameHaeKBjLWWrXRvMCA) {return !isNaN(parseFloat(wzioivFbOcJjimtJvameHaeKBjLWWrXRvMCA)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}