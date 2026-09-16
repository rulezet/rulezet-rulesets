rule sig_20151211_9476e0fb1dd9d4f28510a6350c691d82 {
  meta:
    description = "datamaliciousorder - file 20151211_9476e0fb1dd9d4f28510a6350c691d82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbdebc3fbc4f585aa8b0a98df61362c555a22bf6fa681cc7513ef0a5f123cb50"

  strings:
    $s1  = "function VOKyH(prtmelMqfKQ,RNZKGZMMRLMhM,WXwDdLLn){CngQ=parseInt(prtmelMqfKQ,RNZKGZMMRLMhM);BSHoA=CngQ.toString(WXwDdLLn);return" ascii
    $s2  = "function VOKyH(prtmelMqfKQ,RNZKGZMMRLMhM,WXwDdLLn){CngQ=parseInt(prtmelMqfKQ,RNZKGZMMRLMhM);BSHoA=CngQ.toString(WXwDdLLn);return" ascii
    $s3  = "function jBLQVbj(SYAnTyfLQPtuOrEviQtkyeeqtGbiWbbkYnsI) {return !isNaN(parseFloat(SYAnTyfLQPtuOrEviQtkyeeqtGbiWbbkYnsI)) && isFin" ascii
    $s4  = "function jBLQVbj(SYAnTyfLQPtuOrEviQtkyeeqtGbiWbbkYnsI) {return !isNaN(parseFloat(SYAnTyfLQPtuOrEviQtkyeeqtGbiWbbkYnsI)) && isFin" ascii
    $s5  = "var x=new Array(\"27\",\"2d\",\"2f\",\"2c\",\"2f\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = "var j=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"39\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function MhDKhJzyhoRYiekta(PkcIW){moPVlzIlQTE= '';SWLmfAKcsGM=(-886+886)/948; while(true){if(SWLmfAKcsGM >= (1142+582)/862)break" ascii
    $s8  = "M]++;}SWLmfAKcsGM++;} return moPVlzIlQTE}" fullword ascii
    $s9  = "function bsDRgCKRKflpekzKiReTtiqaJFHlsXvoZrxYzAISgqOLAMkKHNEIwg(QiTtQswuULcGl,NyXEVqZaRZTDow){ return Kqfoa[VOKyH(QiTtQswuULcGl[" ascii
    $s10 = "var j=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"39\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = ";fvzRLVENs[SWLmfAKcsGM]=(-589+589)/469; while(true) { if(fvzRLVENs[SWLmfAKcsGM] > PkcIW[SWLmfAKcsGM].length-(-52+496)/444) { bre" ascii
    $s12 = "function bsDRgCKRKflpekzKiReTtiqaJFHlsXvoZrxYzAISgqOLAMkKHNEIwg(QiTtQswuULcGl,NyXEVqZaRZTDow){ return Kqfoa[VOKyH(QiTtQswuULcGl[" ascii
    $s13 = "var x=new Array(\"27\",\"2d\",\"2f\",\"2c\",\"2f\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = " BSHoA;}function fuTsQwxdmceOWsG(gQGAtBKbKmNAEOhsI){eval(gQGAtBKbKmNAEOhsI)}" fullword ascii
    $s15 = "function MhDKhJzyhoRYiekta(PkcIW){moPVlzIlQTE= '';SWLmfAKcsGM=(-886+886)/948; while(true){if(SWLmfAKcsGM >= (1142+582)/862)break" ascii
    $s16 = "function KmKlxmimwNp(SExioecx,XLnixI){return SExioecx.split(XLnixI)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}