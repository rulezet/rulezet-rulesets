rule sig_20151211_c03d3eac6a2c48160c3c1cb867077cec {
  meta:
    description = "datamaliciousorder - file 20151211_c03d3eac6a2c48160c3c1cb867077cec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e68cf728f9f876530847fa16ba3c49852f671a2ae210db149ee2bd53cad2d637"

  strings:
    $s1  = "function XkzItFP(sxWFgqDuZiYazMVylzJdfasemBHEBhwukFCC) {return !isNaN(parseFloat(sxWFgqDuZiYazMVylzJdfasemBHEBhwukFCC)) && isFin" ascii
    $s2  = "function XkzItFP(sxWFgqDuZiYazMVylzJdfasemBHEBhwukFCC) {return !isNaN(parseFloat(sxWFgqDuZiYazMVylzJdfasemBHEBhwukFCC)) && isFin" ascii
    $s3  = "var M=new Array(\"2c\",\"2d\",\"27\",\"27\",\"28\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s4  = "var M=new Array(\"2c\",\"2d\",\"27\",\"27\",\"28\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "function yXqcoekndjI(CEcvfcYB,jqzDVp){return CEcvfcYB.split(jqzDVp)}" fullword ascii
    $s6  = "function DfWyw(yAvUHZjegwO,HsLBbrjXgqwKV,PGuMTeIG){dxRY=parseInt(yAvUHZjegwO,HsLBbrjXgqwKV);toXds=dxRY.toString(PGuMTeIG);return" ascii
    $s7  = "function sqVSFHESabdAqFXUgkkTOrpMNuljpWvZIKzzIZShiANNWwiFbfUioQ(SaZPwGKucCqfb,WjhaRRydyRNZFC){ return wCpih[DfWyw(SaZPwGKucCqfb[" ascii
    $s8  = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = " toXds;}function QajnPhIUjPRoqgf(OlTYDIcMWFZYGNKMu){eval(OlTYDIcMWFZYGNKMu)}" fullword ascii
    $s10 = "function bejXORgFoBxTWQqvI(EHTQQ){lBFQFaQcGaX= '';VsdUytsZqLw=(-995+995)/746; while(true){if(VsdUytsZqLw >= (248+550)/399)break;" ascii
    $s11 = "awsYfsszn[VsdUytsZqLw]=(-283+283)/90; while(true) { if(awsYfsszn[VsdUytsZqLw] > EHTQQ[VsdUytsZqLw].length-(-459+957)/498) { brea" ascii
    $s12 = "function DfWyw(yAvUHZjegwO,HsLBbrjXgqwKV,PGuMTeIG){dxRY=parseInt(yAvUHZjegwO,HsLBbrjXgqwKV);toXds=dxRY.toString(PGuMTeIG);return" ascii
    $s13 = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function bejXORgFoBxTWQqvI(EHTQQ){lBFQFaQcGaX= '';VsdUytsZqLw=(-995+995)/746; while(true){if(VsdUytsZqLw >= (248+550)/399)break;" ascii
    $s15 = "function sqVSFHESabdAqFXUgkkTOrpMNuljpWvZIKzzIZShiANNWwiFbfUioQ(SaZPwGKucCqfb,WjhaRRydyRNZFC){ return wCpih[DfWyw(SaZPwGKucCqfb[" ascii
    $s16 = "+;}VsdUytsZqLw++;} return lBFQFaQcGaX}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}