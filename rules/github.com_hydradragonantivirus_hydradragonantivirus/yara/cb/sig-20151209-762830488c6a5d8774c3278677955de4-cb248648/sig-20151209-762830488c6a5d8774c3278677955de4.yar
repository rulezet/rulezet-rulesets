rule sig_20151209_762830488c6a5d8774c3278677955de4 {
  meta:
    description = "datamaliciousorder - file 20151209_762830488c6a5d8774c3278677955de4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab1efb84da470c6f436d27a33a1074828f77d1b9565ea18efbee303d47cb7a10"

  strings:
    $s1  = "function juzxU(ueDAJFaTWCX,TYLOGOWaFlLqt,DpupBnlq){gZCq=parseInt(ueDAJFaTWCX,TYLOGOWaFlLqt);vgEgf=gZCq.toString(DpupBnlq);return" ascii
    $s2  = "function juzxU(ueDAJFaTWCX,TYLOGOWaFlLqt,DpupBnlq){gZCq=parseInt(ueDAJFaTWCX,TYLOGOWaFlLqt);vgEgf=gZCq.toString(DpupBnlq);return" ascii
    $s3  = "function KUaNdGzychNyAwRqT(ZQwqg){tfxLABSpSGk= '';for(IxSoIhfuhkq=(-59+59)/316; IxSoIhfuhkq < (233+587)/410; IxSoIhfuhkq++) {Gop" ascii
    $s4  = "function rWggElCobpF(hBpNexdP,VImnUr){return hBpNexdP.split(VImnUr)}" fullword ascii
    $s5  = "}} return tfxLABSpSGk}" fullword ascii
    $s6  = "function KUaNdGzychNyAwRqT(ZQwqg){tfxLABSpSGk= '';for(IxSoIhfuhkq=(-59+59)/316; IxSoIhfuhkq < (233+587)/410; IxSoIhfuhkq++) {Gop" ascii
    $s7  = "function VTBENyFJApVymIvhENqftIjCJMzmKPBxSMosmsMhSvQYwfDVSNUALO(KdurOAoMOsabF,hKtGVzuMWBOSWY){ return lKlLv[juzxU(KdurOAoMOsabF[" ascii
    $s8  = "KPRcKB[IxSoIhfuhkq]=(-792+792)/655; while(true) { if(GopKPRcKB[IxSoIhfuhkq] > ZQwqg[IxSoIhfuhkq].length-(-416+503)/87) { break; " ascii
    $s9  = " vgEgf;}function WXpZsxlrEWudpOJ(jtOEwGJeMhYmBcnIq){eval(jtOEwGJeMhYmBcnIq)}" fullword ascii
    $s10 = "function VTBENyFJApVymIvhENqftIjCJMzmKPBxSMosmsMhSvQYwfDVSNUALO(KdurOAoMOsabF,hKtGVzuMWBOSWY){ return lKlLv[juzxU(KdurOAoMOsabF[" ascii
    $s11 = "function bbUoVEZ(SQCAqBaOOIZaKITXIjTQwcAXtlHUbRThffuL) {return !isNaN(parseFloat(SQCAqBaOOIZaKITXIjTQwcAXtlHUbRThffuL)) && isFin" ascii
    $s12 = "function bbUoVEZ(SQCAqBaOOIZaKITXIjTQwcAXtlHUbRThffuL) {return !isNaN(parseFloat(SQCAqBaOOIZaKITXIjTQwcAXtlHUbRThffuL)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}