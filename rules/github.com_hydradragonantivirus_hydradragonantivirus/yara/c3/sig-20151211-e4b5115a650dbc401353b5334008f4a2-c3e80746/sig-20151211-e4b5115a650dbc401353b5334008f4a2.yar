rule sig_20151211_e4b5115a650dbc401353b5334008f4a2 {
  meta:
    description = "datamaliciousorder - file 20151211_e4b5115a650dbc401353b5334008f4a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9abae6d0f39e7b2b9b9fb51f70b7b45b4ab2e05dab2f5479a5063b4a2dd6004"

  strings:
    $s1  = "function WkIwG(JiVDWOhAFlv,hjHsfpuKIwbxO,TkBoWoSK){aIsJ=parseInt(JiVDWOhAFlv,hjHsfpuKIwbxO);KDmot=aIsJ.toString(TkBoWoSK);return" ascii
    $s2  = "function KwHLhOrJExXvcWQqP(evEYG){TutdPcsQGev= '';XAxWpTnCcoY=(-856+856)/857; while(true){if(XAxWpTnCcoY >= (1027+931)/979)break" ascii
    $s3  = " KDmot;}function nniLovNjNLbklXU(PONqSdveeozKgITMy){eval(PONqSdveeozKgITMy)}" fullword ascii
    $s4  = "var Oo=new Array(\"2d\",\"2b\",\"26\",\"26\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s5  = "function aLMQRRngitLjORmVfcKKUMnlbkKRJiqDxblMathnwoJNCPVajolaxN(KlIThCzgOUWqX,QjkmTwiDqJMCGQ){ return jQSYw[WkIwG(KlIThCzgOUWqX[" ascii
    $s6  = "function KwHLhOrJExXvcWQqP(evEYG){TutdPcsQGev= '';XAxWpTnCcoY=(-856+856)/857; while(true){if(XAxWpTnCcoY >= (1027+931)/979)break" ascii
    $s7  = "function aLMQRRngitLjORmVfcKKUMnlbkKRJiqDxblMathnwoJNCPVajolaxN(KlIThCzgOUWqX,QjkmTwiDqJMCGQ){ return jQSYw[WkIwG(KlIThCzgOUWqX[" ascii
    $s8  = "var Oo=new Array(\"2d\",\"2b\",\"26\",\"26\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s9  = "function WkIwG(JiVDWOhAFlv,hjHsfpuKIwbxO,TkBoWoSK){aIsJ=parseInt(JiVDWOhAFlv,hjHsfpuKIwbxO);KDmot=aIsJ.toString(TkBoWoSK);return" ascii
    $s10 = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"55\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"55\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "Y]++;}XAxWpTnCcoY++;} return TutdPcsQGev}" fullword ascii
    $s13 = "function HpbCiCSDmUB(seBLLnlj,keZiDL){return seBLLnlj.split(keZiDL)}" fullword ascii
    $s14 = ";hurHqphBH[XAxWpTnCcoY]=(-113+113)/487; while(true) { if(hurHqphBH[XAxWpTnCcoY] > evEYG[XAxWpTnCcoY].length-(744+144)/888) { bre" ascii
    $s15 = "function ORjbCVN(ThDFBRlAiJcAnBZXsERFpMnumHgWKrhnfGOH) {return !isNaN(parseFloat(ThDFBRlAiJcAnBZXsERFpMnumHgWKrhnfGOH)) && isFin" ascii
    $s16 = "function ORjbCVN(ThDFBRlAiJcAnBZXsERFpMnumHgWKrhnfGOH) {return !isNaN(parseFloat(ThDFBRlAiJcAnBZXsERFpMnumHgWKrhnfGOH)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}