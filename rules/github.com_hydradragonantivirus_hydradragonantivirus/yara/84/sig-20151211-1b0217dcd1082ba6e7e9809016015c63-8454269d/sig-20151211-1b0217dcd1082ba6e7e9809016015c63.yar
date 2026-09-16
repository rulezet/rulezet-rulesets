rule sig_20151211_1b0217dcd1082ba6e7e9809016015c63 {
  meta:
    description = "datamaliciousorder - file 20151211_1b0217dcd1082ba6e7e9809016015c63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a62a0c9bad90e606498f26e9b2e0e67a833b0567dd9404ae06a0a6845605b081"

  strings:
    $s1  = "function SdHxfyV(rMVCPymztmXovqhsIjLRAYMNIkSIKkdcbXKC) {return !isNaN(parseFloat(rMVCPymztmXovqhsIjLRAYMNIkSIKkdcbXKC)) && isFin" ascii
    $s2  = "function SdHxfyV(rMVCPymztmXovqhsIjLRAYMNIkSIKkdcbXKC) {return !isNaN(parseFloat(rMVCPymztmXovqhsIjLRAYMNIkSIKkdcbXKC)) && isFin" ascii
    $s3  = "eYRrgROnE[fyyKmnFecQd]=(-345+345)/868; while(true) { if(eYRrgROnE[fyyKmnFecQd] > MSSjh[fyyKmnFecQd].length-(-668+735)/67) { brea" ascii
    $s4  = " AfhpJ;}function nlNUMOEobJCrJtF(pvcTIQvGnTkQbrepM){eval(pvcTIQvGnTkQbrepM)}" fullword ascii
    $s5  = "var S=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function nflyMmuMGgQSEzsPQLXeAuwrFFHSnPublEqSTjkNsiyzdolEhAseCH(IVNcltUbJxpjA,McpdVyKDtQCnFk){ return IDtse[RLucJ(IVNcltUbJxpjA[" ascii
    $s7  = "function VtDFRNdVGqz(BjFImrtt,HlzLHx){return BjFImrtt.split(HlzLHx)}" fullword ascii
    $s8  = "function OJLInUEhVciuMoomW(MSSjh){rTaqLQAUJFr= '';fyyKmnFecQd=(-401+401)/459; while(true){if(fyyKmnFecQd >= (784+126)/455)break;" ascii
    $s9  = "var c=new Array(\"27\",\"2b\",\"2f\",\"2d\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s10 = "var c=new Array(\"27\",\"2b\",\"2f\",\"2d\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "function OJLInUEhVciuMoomW(MSSjh){rTaqLQAUJFr= '';fyyKmnFecQd=(-401+401)/459; while(true){if(fyyKmnFecQd >= (784+126)/455)break;" ascii
    $s12 = "function nflyMmuMGgQSEzsPQLXeAuwrFFHSnPublEqSTjkNsiyzdolEhAseCH(IVNcltUbJxpjA,McpdVyKDtQCnFk){ return IDtse[RLucJ(IVNcltUbJxpjA[" ascii
    $s13 = "function RLucJ(WbpKEjyYwTL,BdZWRFWZYWLdT,XJdqMJoK){UTSJ=parseInt(WbpKEjyYwTL,BdZWRFWZYWLdT);AfhpJ=UTSJ.toString(XJdqMJoK);return" ascii
    $s14 = "function RLucJ(WbpKEjyYwTL,BdZWRFWZYWLdT,XJdqMJoK){UTSJ=parseInt(WbpKEjyYwTL,BdZWRFWZYWLdT);AfhpJ=UTSJ.toString(XJdqMJoK);return" ascii
    $s15 = "var S=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = ";}fyyKmnFecQd++;} return rTaqLQAUJFr}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}