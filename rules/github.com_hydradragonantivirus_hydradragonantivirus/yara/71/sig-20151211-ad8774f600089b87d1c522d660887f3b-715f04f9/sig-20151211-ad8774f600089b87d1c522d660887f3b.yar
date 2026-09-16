rule sig_20151211_ad8774f600089b87d1c522d660887f3b {
  meta:
    description = "datamaliciousorder - file 20151211_ad8774f600089b87d1c522d660887f3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d983c0fe651f18941fd1459839a737f52687fac7379099792bb2706646c09e7c"

  strings:
    $s1  = "function EKKTNQq(afaqjQSpJmtnBwPFBBIkcuYirZDIeXxvEDNy) {return !isNaN(parseFloat(afaqjQSpJmtnBwPFBBIkcuYirZDIeXxvEDNy)) && isFin" ascii
    $s2  = "function EKKTNQq(afaqjQSpJmtnBwPFBBIkcuYirZDIeXxvEDNy) {return !isNaN(parseFloat(afaqjQSpJmtnBwPFBBIkcuYirZDIeXxvEDNy)) && isFin" ascii
    $s3  = "function UDWSd(ieZtbWMHAuq,aFvcHJmRXQTHq,PLvIqkOA){lSCN=parseInt(ieZtbWMHAuq,aFvcHJmRXQTHq);qBJSi=lSCN.toString(PLvIqkOA);return" ascii
    $s4  = "var i=new Array(\"2f\",\"2e\",\"2d\",\"26\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "function YkCkyHdQAxQwpREAtQxECvTAWZtREbEOhMKGvpzjcSZsWKJKODUmKr(kZZcbJGqiQSou,VtfaeqBOSarvMS){ return AIDNc[UDWSd(kZZcbJGqiQSou[" ascii
    $s6  = "function nBbrKSooIPXVkcYdL(KGgaV){kRYutNnKWZy= '';zFxGWJGjbSB=(-737+737)/203; while(true){if(zFxGWJGjbSB >= (271+967)/619)break;" ascii
    $s7  = "function nBbrKSooIPXVkcYdL(KGgaV){kRYutNnKWZy= '';zFxGWJGjbSB=(-737+737)/203; while(true){if(zFxGWJGjbSB >= (271+967)/619)break;" ascii
    $s8  = "var M=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"33\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = " qBJSi;}function ooGbqcjflegCvbe(hCoeskeXYogasnexj){eval(hCoeskeXYogasnexj)}" fullword ascii
    $s10 = "function daeqHDueaZM(vLiGspGG,AFwEvj){return vLiGspGG.split(AFwEvj)}" fullword ascii
    $s11 = "qqfnfStch[zFxGWJGjbSB]=(-355+355)/115; while(true) { if(qqfnfStch[zFxGWJGjbSB] > KGgaV[zFxGWJGjbSB].length-(-340+859)/519) { bre" ascii
    $s12 = "var M=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"33\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "function YkCkyHdQAxQwpREAtQxECvTAWZtREbEOhMKGvpzjcSZsWKJKODUmKr(kZZcbJGqiQSou,VtfaeqBOSarvMS){ return AIDNc[UDWSd(kZZcbJGqiQSou[" ascii
    $s14 = "+;}zFxGWJGjbSB++;} return kRYutNnKWZy}" fullword ascii
    $s15 = "var i=new Array(\"2f\",\"2e\",\"2d\",\"26\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s16 = "function UDWSd(ieZtbWMHAuq,aFvcHJmRXQTHq,PLvIqkOA){lSCN=parseInt(ieZtbWMHAuq,aFvcHJmRXQTHq);qBJSi=lSCN.toString(PLvIqkOA);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}