rule sig_20151211_75d64d62f8fdd668a559dbb6dab093ee {
  meta:
    description = "datamaliciousorder - file 20151211_75d64d62f8fdd668a559dbb6dab093ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64f6df1c426f6ab85287e846679ea6b8bdb7b7d1175bc439af644ba946014ee"

  strings:
    $s1  = "function KnUkXDf(YrlVxGTtYIwaVpjpPBxreuHyASTXhQEAffdR) {return !isNaN(parseFloat(YrlVxGTtYIwaVpjpPBxreuHyASTXhQEAffdR)) && isFin" ascii
    $s2  = "function KnUkXDf(YrlVxGTtYIwaVpjpPBxreuHyASTXhQEAffdR) {return !isNaN(parseFloat(YrlVxGTtYIwaVpjpPBxreuHyASTXhQEAffdR)) && isFin" ascii
    $s3  = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"43\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "var A=new Array(\"26\",\"27\",\"2b\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "SNtpSdrVW[ADIxYuuhphC]=(-212+212)/261; while(true) { if(SNtpSdrVW[ADIxYuuhphC] > Ocbxk[ADIxYuuhphC].length-(-186+608)/422) { bre" ascii
    $s6  = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"43\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function YCrcu(SrfbQTqskoi,xLOUSkewpCVlf,yxuONDMo){lxew=parseInt(SrfbQTqskoi,xLOUSkewpCVlf);Fglyo=lxew.toString(yxuONDMo);return" ascii
    $s8  = "]++;}ADIxYuuhphC++;} return eHtvzweDKeP}" fullword ascii
    $s9  = " Fglyo;}function OGIFfcpAyoyVkBQ(OUSZLZKMuEUiVyGMT){eval(OUSZLZKMuEUiVyGMT)}" fullword ascii
    $s10 = "function YCrcu(SrfbQTqskoi,xLOUSkewpCVlf,yxuONDMo){lxew=parseInt(SrfbQTqskoi,xLOUSkewpCVlf);Fglyo=lxew.toString(yxuONDMo);return" ascii
    $s11 = "function aSqGoURlnEkcNLXQVzWPkrlUZdOkKOyawhQWLwPQQkcvEIbyelBCxz(LesiyqumdomqD,eGqrRsvRvfarBJ){ return loLBK[YCrcu(LesiyqumdomqD[" ascii
    $s12 = "var A=new Array(\"26\",\"27\",\"2b\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function jHHmxzaWDOqYrgwas(Ocbxk){eHtvzweDKeP= '';ADIxYuuhphC=(-623+623)/185; while(true){if(ADIxYuuhphC >= (249+735)/492)break;" ascii
    $s14 = "function jHHmxzaWDOqYrgwas(Ocbxk){eHtvzweDKeP= '';ADIxYuuhphC=(-623+623)/185; while(true){if(ADIxYuuhphC >= (249+735)/492)break;" ascii
    $s15 = "function aSqGoURlnEkcNLXQVzWPkrlUZdOkKOyawhQWLwPQQkcvEIbyelBCxz(LesiyqumdomqD,eGqrRsvRvfarBJ){ return loLBK[YCrcu(LesiyqumdomqD[" ascii
    $s16 = "function RLUeDPqhnAM(mbraDgXf,sJWeJu){return mbraDgXf.split(sJWeJu)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}