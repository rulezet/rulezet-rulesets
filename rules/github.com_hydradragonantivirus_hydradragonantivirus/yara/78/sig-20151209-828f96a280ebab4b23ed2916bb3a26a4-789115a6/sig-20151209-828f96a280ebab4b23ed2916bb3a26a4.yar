rule sig_20151209_828f96a280ebab4b23ed2916bb3a26a4 {
  meta:
    description = "datamaliciousorder - file 20151209_828f96a280ebab4b23ed2916bb3a26a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad78a91ae7c35b5fd9aa7da3c02283b2735e93be03d9f020cca8b1e8745ce86a"

  strings:
    $s1  = "function sRFCppX(yKnrJnaJLxldpcEyJDehPnPNBDdiitUvnidt) {return !isNaN(parseFloat(yKnrJnaJLxldpcEyJDehPnPNBDdiitUvnidt)) && isFin" ascii
    $s2  = "function sRFCppX(yKnrJnaJLxldpcEyJDehPnPNBDdiitUvnidt) {return !isNaN(parseFloat(yKnrJnaJLxldpcEyJDehPnPNBDdiitUvnidt)) && isFin" ascii
    $s3  = "xibsGpD[cgqIDWZnDqR]=(-996+996)/338; while(true) { if(LtxibsGpD[cgqIDWZnDqR] > GBpEQ[cgqIDWZnDqR].length-(-144+912)/768) { break" ascii
    $s4  = " khAzv;}function PrvdWobQspmhobO(FYrgvbnUMgowioJJF){eval(FYrgvbnUMgowioJJF)}" fullword ascii
    $s5  = "function bdYgAeCKzlk(EgHqNEOF,LAUouA){return EgHqNEOF.split(LAUouA)}" fullword ascii
    $s6  = "function JqRsCiOwqolHbQdOM(GBpEQ){JuugTArBlnV= '';for(cgqIDWZnDqR=(-335+335)/56; cgqIDWZnDqR < (-300+424)/62; cgqIDWZnDqR++) {Lt" ascii
    $s7  = "function ZmJPR(OnYFUOCgCNi,zOXaAXXkEWvAS,oHNmAUes){flOw=parseInt(OnYFUOCgCNi,zOXaAXXkEWvAS);khAzv=flOw.toString(oHNmAUes);return" ascii
    $s8  = "+;}} return JuugTArBlnV}" fullword ascii
    $s9  = "function ZmJPR(OnYFUOCgCNi,zOXaAXXkEWvAS,oHNmAUes){flOw=parseInt(OnYFUOCgCNi,zOXaAXXkEWvAS);khAzv=flOw.toString(oHNmAUes);return" ascii
    $s10 = "function evLdKCNQQEwxsouHxQNCqjpeDXfslKQeWaLfZlPWAtOTYqJcaSwsBh(HBayZKNsNqFpj,PUFCDdJdDwxoVW){ return JVNsT[ZmJPR(HBayZKNsNqFpj[" ascii
    $s11 = "function JqRsCiOwqolHbQdOM(GBpEQ){JuugTArBlnV= '';for(cgqIDWZnDqR=(-335+335)/56; cgqIDWZnDqR < (-300+424)/62; cgqIDWZnDqR++) {Lt" ascii
    $s12 = "function evLdKCNQQEwxsouHxQNCqjpeDXfslKQeWaLfZlPWAtOTYqJcaSwsBh(HBayZKNsNqFpj,PUFCDdJdDwxoVW){ return JVNsT[ZmJPR(HBayZKNsNqFpj[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}