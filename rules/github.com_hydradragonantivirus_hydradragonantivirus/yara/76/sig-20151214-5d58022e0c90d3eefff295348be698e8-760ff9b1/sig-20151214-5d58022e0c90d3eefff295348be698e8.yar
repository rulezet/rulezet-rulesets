rule sig_20151214_5d58022e0c90d3eefff295348be698e8 {
  meta:
    description = "datamaliciousorder - file 20151214_5d58022e0c90d3eefff295348be698e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13a9d395f5736815d8b1961211353c289ccff1b1f1da4d1bde66cda9f27794a3"

  strings:
    $s1  = "ath.pow(Math.cos(489), 2) - 1)); while(true) { if(tkpqbDPaI[PmxVMzkfFGu] > odkFm[PmxVMzkfFGu].length-(-515+895)/380) { break; } " ascii
    $s2  = "ow(Math.cos(170), 2) - 1)));} tkpqbDPaI[PmxVMzkfFGu]++;}} return IZkfgzCnidR}" fullword ascii
    $s3  = "function gknENADFyrTDhULOZ(odkFm){IZkfgzCnidR= j[1806];for(PmxVMzkfFGu=Math.round((Math.pow(Math.sin(718), 2) + Math.pow(Math.co" ascii
    $s4  = "function gknENADFyrTDhULOZ(odkFm){IZkfgzCnidR= j[1806];for(PmxVMzkfFGu=Math.round((Math.pow(Math.sin(718), 2) + Math.pow(Math.co" ascii
    $s5  = "function O(VswUEOiLOnxA,hhoBzAJnPScUiM){VswUEOiLOnxA.push(hhoBzAJnPScUiM);}function y1(drSVVSGtHFEhkZvt){if(WOrjssF(drSVVSGtHFEh" ascii
    $s6  = "kZvt)) {return (String.fromCharCode(drSVVSGtHFEhkZvt) + String.fromCharCode((19862+958)/347));}}" fullword ascii
    $s7  = "function WOrjssF(KFRoigDBFKUvJVOANokFaaMnHrXjMtlkFCLz) {return !isNaN(parseFloat(KFRoigDBFKUvJVOANokFaaMnHrXjMtlkFCLz)) && isFin" ascii
    $s8  = "function WOrjssF(KFRoigDBFKUvJVOANokFaaMnHrXjMtlkFCLz) {return !isNaN(parseFloat(KFRoigDBFKUvJVOANokFaaMnHrXjMtlkFCLz)) && isFin" ascii
    $s9  = "function yTKFE(fhwaXlvEIae,FmpmAPhtTTXOr,KVQPghcK){QttS=parseInt(fhwaXlvEIae,FmpmAPhtTTXOr);LcGov=QttS.toString(KVQPghcK);return" ascii
    $s10 = "function O(VswUEOiLOnxA,hhoBzAJnPScUiM){VswUEOiLOnxA.push(hhoBzAJnPScUiM);}function y1(drSVVSGtHFEhkZvt){if(WOrjssF(drSVVSGtHFEh" ascii
    $s11 = " LcGov;}function tRUoOpEWGwuQsvb(YjNklSLejWJpxrOxa,scGayiixishKXMbLyxQTaErkpQIJYmvepP,IETAVtOYFrZXQliglxZjVbMlbIBNuSYkcKN){eval(" ascii
    $s12 = "function tRUoOpEWGwuQsvb(YjNklSLejWJpxrOxa){eval(YjNklSLejWJpxrOxa)}" fullword ascii
    $s13 = "function RkPKfUVdmlygrDkqIULRneXrKJQuaIOObgVsKaIXNigBGtJpobzizu(ARMELZpsbczwk,nQMtXrYsGlbbau){ return vDGsmdC[JnqxMXmf[yTKFE(ARM" ascii
    $s14 = "function yTKFE(fhwaXlvEIae,FmpmAPhtTTXOr,KVQPghcK){QttS=parseInt(fhwaXlvEIae,FmpmAPhtTTXOr);LcGov=QttS.toString(KVQPghcK);return" ascii
    $s15 = "function RkPKfUVdmlygrDkqIULRneXrKJQuaIOObgVsKaIXNigBGtJpobzizu(ARMELZpsbczwk,nQMtXrYsGlbbau){ return vDGsmdC[JnqxMXmf[yTKFE(ARM" ascii
    $s16 = "var j=new Array();" fullword ascii
    $s17 = "function vAYnkRlLxZt(NsaMljLK,EKyCAg){return NsaMljLK.split(EKyCAg)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}