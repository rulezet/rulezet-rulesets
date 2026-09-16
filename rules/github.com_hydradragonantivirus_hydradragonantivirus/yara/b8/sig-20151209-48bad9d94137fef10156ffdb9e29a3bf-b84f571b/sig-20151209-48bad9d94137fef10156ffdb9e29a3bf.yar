rule sig_20151209_48bad9d94137fef10156ffdb9e29a3bf {
  meta:
    description = "datamaliciousorder - file 20151209_48bad9d94137fef10156ffdb9e29a3bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fe4570bf9cb67b5da4d8883ebbb561f36c6a762eb7790b8b5220eaa705e96a"

  strings:
    $s1  = "function AnlsqEV(dhuKELGrMEkTCoZdFvvUeiZWiMTYlOIOyokp) {return !isNaN(parseFloat(dhuKELGrMEkTCoZdFvvUeiZWiMTYlOIOyokp)) && isFin" ascii
    $s2  = "function AnlsqEV(dhuKELGrMEkTCoZdFvvUeiZWiMTYlOIOyokp) {return !isNaN(parseFloat(dhuKELGrMEkTCoZdFvvUeiZWiMTYlOIOyokp)) && isFin" ascii
    $s3  = "function vOOFOvUQMQU(fUdgSMwh,kXRePy){return fUdgSMwh.split(kXRePy)}" fullword ascii
    $s4  = "function BIIfUIejdCRjzuebo(iZhDq){EPlEyAvmvKJ= '';for(LBmjSZYhgbs=(-656+656)/160; LBmjSZYhgbs < (731+985)/858; LBmjSZYhgbs++) {a" ascii
    $s5  = "function YBNut(rWJUftyAlnA,PndNvQXpweiNn,hAnWITYZ){OOeK=parseInt(rWJUftyAlnA,PndNvQXpweiNn);UhqRh=OOeK.toString(hAnWITYZ);return" ascii
    $s6  = "YeahuGPr[LBmjSZYhgbs]=(-369+369)/748; while(true) { if(aYeahuGPr[LBmjSZYhgbs] > iZhDq[LBmjSZYhgbs].length-(-771+927)/156) { brea" ascii
    $s7  = "function BIIfUIejdCRjzuebo(iZhDq){EPlEyAvmvKJ= '';for(LBmjSZYhgbs=(-656+656)/160; LBmjSZYhgbs < (731+985)/858; LBmjSZYhgbs++) {a" ascii
    $s8  = "++;}} return EPlEyAvmvKJ}" fullword ascii
    $s9  = "function LFJfwYQlaWjENpTcedCJOjTmWUXclWotfHdUqgZnFuvAdcFsMYvtsK(CjtOxkDsAgJIw,xwIxxDeyxacAGX){ return jRZCk[YBNut(CjtOxkDsAgJIw[" ascii
    $s10 = "function LFJfwYQlaWjENpTcedCJOjTmWUXclWotfHdUqgZnFuvAdcFsMYvtsK(CjtOxkDsAgJIw,xwIxxDeyxacAGX){ return jRZCk[YBNut(CjtOxkDsAgJIw[" ascii
    $s11 = "function YBNut(rWJUftyAlnA,PndNvQXpweiNn,hAnWITYZ){OOeK=parseInt(rWJUftyAlnA,PndNvQXpweiNn);UhqRh=OOeK.toString(hAnWITYZ);return" ascii
    $s12 = " UhqRh;}function MvfVqevBbkDvhWw(OcaPBZNOastPWhCYM){eval(OcaPBZNOastPWhCYM)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}