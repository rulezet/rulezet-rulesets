rule sig_20160411_ccfa199afcbf254236ea5f262e4052ab {
  meta:
    description = "datamaliciousorder - file 20160411_ccfa199afcbf254236ea5f262e4052ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89e2bb2c07b9d041222649234369b6e3e97a619b7d4a53dd2b92e2361779b02d"

  strings:
    $s1  = "function rgPeget(tiJn) {" fullword ascii
    $s2  = "return LTCONXV[0] + LTCONXV[2] + LTCONXV[4] + \".F\" + LTCONXV[7] + LTCONXV[9] + LTCONXV[12] + LTCONXV[14];" fullword ascii
    $s3  = "var TE = true  , HHcB = yQV[7] + yQV[9] + yQV[11];" fullword ascii
    $s4  = "var yQV = (\"2.XMLHTTP rfLsdld QwlNh XML ream St pCrTqqDT AD PcTevMV O qzXU D\").split(\" \");" fullword ascii
    $s5  = "qSVD.open(IEtXR,CWicM,false);" fullword ascii
    $s6  = "return tiJn[ZqyRvcy[0]+ZqyRvcy[1]];" fullword ascii
    $s7  = "return noHwHax[0];" fullword ascii
    $s8  = "if (OfMWB == 904-704){return true;} else {return false;}" fullword ascii
    $s9  = "function jBsIV(zIjNsQ) {" fullword ascii
    $s10 = "function pBdX(MJPnN,jlRnY) {" fullword ascii
    $s11 = "return zIjNsQ[muLX[478-478]]=242-242;" fullword ascii
    $s12 = "return KBxuoju(Ro,dcOzsn+kegLl[600-592]);" fullword ascii
    $s13 = "VMH = Q; break; " fullword ascii
    $s14 = "return deD.size;" fullword ascii
    $s15 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s16 = "function Todq(dFrTj) {" fullword ascii
    $s17 = "return \"xJVQAkMkrFrqUO\";" fullword ascii
    $s18 = "function VGrfgHoMa(FPchW) {" fullword ascii
    $s19 = "function oRdmT(MMPDHyFk,sWWI) {" fullword ascii
    $s20 = "return SGxTKmm;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}