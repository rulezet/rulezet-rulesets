rule sig_20151210_9fcb8573c3b05e067d594be122942695 {
  meta:
    description = "datamaliciousorder - file 20151210_9fcb8573c3b05e067d594be122942695.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "275f01531a2bbff6e6e89a901e21f235c75031c3ade269c6f666c6b7dd1dfd7a"

  strings:
    $s1  = "function TQFvmrM(TAaorgCOoYwHThPFItPaYPTQFsBnfKufltrX) {return !isNaN(parseFloat(TAaorgCOoYwHThPFItPaYPTQFsBnfKufltrX)) && isFin" ascii
    $s2  = "function TQFvmrM(TAaorgCOoYwHThPFItPaYPTQFsBnfKufltrX) {return !isNaN(parseFloat(TAaorgCOoYwHThPFItPaYPTQFsBnfKufltrX)) && isFin" ascii
    $s3  = "function sccykgBKysQlIyjcVrSJJhHbJNKtnBTxDDGZdaryvLIcwxnjLgfLDK(GZhvKohXmzhOz,DzpeivevJcWExC){ return XISJl[uUNMO(GZhvKohXmzhOz[" ascii
    $s4  = "function WvXQDLgaEur(VlhNEKRz,xFDNPt){return VlhNEKRz.split(xFDNPt)}" fullword ascii
    $s5  = "function hdqqlCkDwKfCMIFYg(ZEGwQ){uZTxZzWYZSe= '';for(LIQhjcBGgBh=(-299+299)/858; LIQhjcBGgBh < (245+673)/459; LIQhjcBGgBh++) {A" ascii
    $s6  = "function uUNMO(OqkghzwebQr,eeAsciMgnrKyu,pbHzEzJs){LfaD=parseInt(OqkghzwebQr,eeAsciMgnrKyu);ArKOD=LfaD.toString(pbHzEzJs);return" ascii
    $s7  = "function sccykgBKysQlIyjcVrSJJhHbJNKtnBTxDDGZdaryvLIcwxnjLgfLDK(GZhvKohXmzhOz,DzpeivevJcWExC){ return XISJl[uUNMO(GZhvKohXmzhOz[" ascii
    $s8  = "function uUNMO(OqkghzwebQr,eeAsciMgnrKyu,pbHzEzJs){LfaD=parseInt(OqkghzwebQr,eeAsciMgnrKyu);ArKOD=LfaD.toString(pbHzEzJs);return" ascii
    $s9  = "ZeyXlEAQ[LIQhjcBGgBh]=(-75+75)/807; while(true) { if(AZeyXlEAQ[LIQhjcBGgBh] > ZEGwQ[LIQhjcBGgBh].length-(-291+961)/670) { break;" ascii
    $s10 = " ArKOD;}function odEznSigTIneBCn(jldvSRrGbkwTltpTt){eval(jldvSRrGbkwTltpTt)}" fullword ascii
    $s11 = ";}} return uZTxZzWYZSe}" fullword ascii
    $s12 = "function hdqqlCkDwKfCMIFYg(ZEGwQ){uZTxZzWYZSe= '';for(LIQhjcBGgBh=(-299+299)/858; LIQhjcBGgBh < (245+673)/459; LIQhjcBGgBh++) {A" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}