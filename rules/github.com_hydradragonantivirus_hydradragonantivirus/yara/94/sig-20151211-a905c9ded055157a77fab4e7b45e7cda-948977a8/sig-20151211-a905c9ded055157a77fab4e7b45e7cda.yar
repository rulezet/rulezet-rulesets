rule sig_20151211_a905c9ded055157a77fab4e7b45e7cda {
  meta:
    description = "datamaliciousorder - file 20151211_a905c9ded055157a77fab4e7b45e7cda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9a049e14b46912c9e54ce87ee64ac26287196d69b7b9bbb0925b0256f60c119"

  strings:
    $s1  = "function PgCsVmS(UktJzowTxnyrkryqcZjVadwyXUIBKsMRyluY) {return !isNaN(parseFloat(UktJzowTxnyrkryqcZjVadwyXUIBKsMRyluY)) && isFin" ascii
    $s2  = "function PgCsVmS(UktJzowTxnyrkryqcZjVadwyXUIBKsMRyluY) {return !isNaN(parseFloat(UktJzowTxnyrkryqcZjVadwyXUIBKsMRyluY)) && isFin" ascii
    $s3  = "var v=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "++;}joNVPtLQWAa++;} return DGVeMlISnLn}" fullword ascii
    $s5  = "function SNePVbPZZknuGnXlw(hBbVQ){DGVeMlISnLn= '';joNVPtLQWAa=(-716+716)/893; while(true){if(joNVPtLQWAa >= (1567+1)/784)break;m" ascii
    $s6  = "function OaOLcCWYFde(eIzrSisl,yyHLDh){return eIzrSisl.split(yyHLDh)}" fullword ascii
    $s7  = "function FpmYNteLRPoWwYtONynAFRTbprnqQxfrmckoaItdHzzSEJECmhsnOz(moFkoXvfnDZgH,XHvShbvOautNVI){ return yLYbP[xvQGQ(moFkoXvfnDZgH[" ascii
    $s8  = "var M=new Array(\"27\",\"27\",\"2c\",\"2d\",\"2c\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "var M=new Array(\"27\",\"27\",\"2c\",\"2d\",\"2c\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "ctpffgaF[joNVPtLQWAa]=(-177+177)/808; while(true) { if(mctpffgaF[joNVPtLQWAa] > hBbVQ[joNVPtLQWAa].length-(-59+989)/930) { break" ascii
    $s11 = "function FpmYNteLRPoWwYtONynAFRTbprnqQxfrmckoaItdHzzSEJECmhsnOz(moFkoXvfnDZgH,XHvShbvOautNVI){ return yLYbP[xvQGQ(moFkoXvfnDZgH[" ascii
    $s12 = "function xvQGQ(vMtpJrGzbYm,sqQQlgtxGSuTq,WZspgydX){ShfU=parseInt(vMtpJrGzbYm,sqQQlgtxGSuTq);uqFeK=ShfU.toString(WZspgydX);return" ascii
    $s13 = "var v=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function xvQGQ(vMtpJrGzbYm,sqQQlgtxGSuTq,WZspgydX){ShfU=parseInt(vMtpJrGzbYm,sqQQlgtxGSuTq);uqFeK=ShfU.toString(WZspgydX);return" ascii
    $s15 = "function SNePVbPZZknuGnXlw(hBbVQ){DGVeMlISnLn= '';joNVPtLQWAa=(-716+716)/893; while(true){if(joNVPtLQWAa >= (1567+1)/784)break;m" ascii
    $s16 = " uqFeK;}function zbYVSOpeuBpcoSG(wqUfvfCNnCdhLljTD){eval(wqUfvfCNnCdhLljTD)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}