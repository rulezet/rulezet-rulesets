rule sig_20160303_86bae53fc57b9e95cd294e672b760193 {
  meta:
    description = "datamaliciousorder - file 20160303_86bae53fc57b9e95cd294e672b760193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9394776f17ab7db84090b34d0b9151b9718da87c1483987e3f3774610a5d4b93"

  strings:
    $s1  = "var dEkAL = \"rrIwcI CXV pt.Shell JBSUlUD Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return ZgsEswp[0] + ZgsEswp[2] + ZgsEswp[4] + \".F\" + ZgsEswp[7] + ZgsEswp[9] + ZgsEswp[12] + ZgsEswp[14];" fullword ascii
    $s3  = "var Rs = true  , JYlK = uMf[7] + \"\" + uMf[9];" fullword ascii
    $s4  = "var uMf = (bhP + \"TTP\" + \" PBzQEoc aqhhe XML ream St ZMGMfpQp AD eOYHmVo OD\").split(\" \");" fullword ascii
    $s5  = "KgALE.open(sbUag,qhaJL,false);" fullword ascii
    $s6  = "var ZgsEswp = \"Sc ELVJpfP r zsRkfIGIY ipting fjShAYV DZD ile MTRhuObTsacNWA System VD MeYGj Obj ZCdhWP ect iUMixck\".split(\" " ascii
    $s7  = "if(t>=p.length) {break;}" fullword ascii
    $s8  = "return pVZcdXL" fullword ascii
    $s9  = "function ryIN(FTvTB) {" fullword ascii
    $s10 = "function cePikeHin(GfOkYhEBjvE) {" fullword ascii
    $s11 = "if (iSvRG > 178192-344){return true;} else {return false;}" fullword ascii
    $s12 = "function VyTY(NzBWe) {" fullword ascii
    $s13 = "function dWeSbitJK(JDdEc,UBXAN,GysLW) {" fullword ascii
    $s14 = "function QCmh(qsAZO,NejDk) {" fullword ascii
    $s15 = "function PyYr(HlyQT) {" fullword ascii
    $s16 = "function sLAcJFZ(pPaQ) {" fullword ascii
    $s17 = "function LyNC(jRRqX,esARG) {" fullword ascii
    $s18 = "if (Kfpdv == 745-545){return true;} else {return false;}" fullword ascii
    $s19 = "function gZEBlTdx() {" fullword ascii
    $s20 = "function Rssm(KgALE,qhaJL,sbUag) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}