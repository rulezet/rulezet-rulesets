rule sig_20151211_2b5711133e45ed6280ff303d3d4ac3f1 {
  meta:
    description = "datamaliciousorder - file 20151211_2b5711133e45ed6280ff303d3d4ac3f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f648c0161d749c20b53d212b13482009dc41b0667a9a6b36de3c309358e7ab68"

  strings:
    $s1  = "function YIGJlFM(eBzqsrfMFAHlWWddBhlXDkFgAqKtQtRbBiUA) {return !isNaN(parseFloat(eBzqsrfMFAHlWWddBhlXDkFgAqKtQtRbBiUA)) && isFin" ascii
    $s2  = "function YIGJlFM(eBzqsrfMFAHlWWddBhlXDkFgAqKtQtRbBiUA) {return !isNaN(parseFloat(eBzqsrfMFAHlWWddBhlXDkFgAqKtQtRbBiUA)) && isFin" ascii
    $s3  = "function bfjfuQqByzRyymANt(mXrDb){wkRmFSVYyYb= '';vpwLiDocQET=(-339+339)/312; while(true){if(vpwLiDocQET >= (-246+590)/172)break" ascii
    $s4  = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3b\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3b\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = " wMpXv;}function GsaRSVYIpdcKpEU(tBVEoiEVWPBXTCWYo){eval(tBVEoiEVWPBXTCWYo)}" fullword ascii
    $s7  = "++;}vpwLiDocQET++;} return wkRmFSVYyYb}" fullword ascii
    $s8  = "function vSIPQ(YmyoEizuIRQ,mwqnLKPGDegGY,RaykXXcb){pyzh=parseInt(YmyoEizuIRQ,mwqnLKPGDegGY);wMpXv=pyzh.toString(RaykXXcb);return" ascii
    $s9  = "var m=new Array(\"28\",\"2f\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s10 = "function bfjfuQqByzRyymANt(mXrDb){wkRmFSVYyYb= '';vpwLiDocQET=(-339+339)/312; while(true){if(vpwLiDocQET >= (-246+590)/172)break" ascii
    $s11 = "function zZrbjYKmERjNJyHMZAdcOQXSIEBAVPmENTxpuagIDeHDZTFRuOegDd(ixmKIimFDeNPw,ndStUMrUPtsVFY){ return mcndw[vSIPQ(ixmKIimFDeNPw[" ascii
    $s12 = ";ktGiVHHUv[vpwLiDocQET]=(-85+85)/800; while(true) { if(ktGiVHHUv[vpwLiDocQET] > mXrDb[vpwLiDocQET].length-(-503+990)/487) { brea" ascii
    $s13 = "function vSIPQ(YmyoEizuIRQ,mwqnLKPGDegGY,RaykXXcb){pyzh=parseInt(YmyoEizuIRQ,mwqnLKPGDegGY);wMpXv=pyzh.toString(RaykXXcb);return" ascii
    $s14 = "function zZrbjYKmERjNJyHMZAdcOQXSIEBAVPmENTxpuagIDeHDZTFRuOegDd(ixmKIimFDeNPw,ndStUMrUPtsVFY){ return mcndw[vSIPQ(ixmKIimFDeNPw[" ascii
    $s15 = "var m=new Array(\"28\",\"2f\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s16 = "function iLDajezOaPC(wjsPZcLD,pxJkrC){return wjsPZcLD.split(pxJkrC)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}