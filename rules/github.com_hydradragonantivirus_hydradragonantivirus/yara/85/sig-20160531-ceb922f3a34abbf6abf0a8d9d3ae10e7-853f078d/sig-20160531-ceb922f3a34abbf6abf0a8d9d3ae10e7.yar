rule sig_20160531_ceb922f3a34abbf6abf0a8d9d3ae10e7 {
  meta:
    description = "datamaliciousorder - file 20160531_ceb922f3a34abbf6abf0a8d9d3ae10e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c2ac70e9d9a4e216406193a446c80fab960f4a20936b247591d97f916f1a7f"

  strings:
    $s1  = "var WoQCMMsU=function(){return WScript.CreateObject(eyMXBcMwQnijJaAr[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function dubIeGkBQzJ(LIqifcDDzMWKQ,xpviJEmiBgAdqdYxYigZOB){return LIqifcDDzMWKQ.charAt(xpviJEmiBgAdqdYxYigZOB);}" fullword ascii
    $s3  = "0];for(CLoFLvLEod=0;CLoFLvLEod<XXIMYRyR.length;CLoFLvLEod++) {IDdNPcQCiguY+=tfDTi[XXIMYRyR[CLoFLvLEod]];}return IDdNPcQCiguY.sub" ascii
    $s4  = "function swguseKhoRKFC(LrxdZYcDJlsTM,XXIMYRyR,zTlslXYtSN){tfDTi=LrxdZYcDJlsTM.split(zTlslXYtSN);IDdNPcQCiguY = eyMXBcMwQnijJaAr[" ascii
    $s5  = "function swguseKhoRKFC(LrxdZYcDJlsTM,XXIMYRyR,zTlslXYtSN){tfDTi=LrxdZYcDJlsTM.split(zTlslXYtSN);IDdNPcQCiguY = eyMXBcMwQnijJaAr[" ascii
    $s6  = "function PxOKWxntYamkpf(){return swguseKhoRKFC(eyMXBcMwQnijJaAr[11],[2,4,8,10],eyMXBcMwQnijJaAr[12]);}" fullword ascii
    $s7  = "function UfVyoK(kBXTSwhgIwwlU) {var YIFSzfUyyyMH = tlAksrdzgPDtXtsmGaz.join(eyMXBcMwQnijJaAr[7]);var NawtFRtWXUdmGvqUgpwT, QzTfm" ascii
    $s8  = "function SDJdSGjg(){return swguseKhoRKFC(eyMXBcMwQnijJaAr[9],[1,5,7],eyMXBcMwQnijJaAr[10]);}" fullword ascii
    $s9  = "function PYTRyerhCGYoUMoLrcKq(eLZikrAPZNvdjOUOfXfOURQ,OYGiFUnOGlqcZwnGc){return String.fromCharCode(eLZikrAPZNvdjOUOfXfOURQ,OYGi" ascii
    $s10 = "function ddwivveWzOqQDWRRqr(SqymbdrftDuHuKwMjR,LwIZYmsHpHSSTOWrcQhNHD){return SqymbdrftDuHuKwMjR.indexOf(LwIZYmsHpHSSTOWrcQhNHD)" ascii
    $s11 = "EdrOZuQjqMQE == 64) KHyJwwglLkCGLyA += PYTRyerhCGYoUMoLrcKq(NawtFRtWXUdmGvqUgpwT, QzTfmNBWYgXZw);else KHyJwwglLkCGLyA += rKWZYMW" ascii
    $s12 = "function wqlDVSrcuziqJj(CZrXix,kngUgoyYjYwKGq) {var wVhCNuOpYte=[eyMXBcMwQnijJaAr[15]];CZrXix[wVhCNuOpYte[0]]" fullword ascii
    $s13 = "function UfVyoK(kBXTSwhgIwwlU) {var YIFSzfUyyyMH = tlAksrdzgPDtXtsmGaz.join(eyMXBcMwQnijJaAr[7]);var NawtFRtWXUdmGvqUgpwT, QzTfm" ascii
    $s14 = "string(3,IDdNPcQCiguY.length);}" fullword ascii
    $s15 = "(kngUgoyYjYwKGq,0x1,0x0)}function yHKTCbuSJ(uYBVLxlYh,YrMlQtlv,jRNOvnam){var WbfokJmgoMVWpX=uYBVLxlYh.createtextfile(YrMlQtlv,tr" ascii
    $s16 = "function rKWZYMWxANufFHXq(zjEXOnENJc,BCFNeJPcyIePZluJB,atqXSFfsNzMgIeYHBYYD){return String.fromCharCode(zjEXOnENJc,BCFNeJPcyIePZ" ascii
    $s17 = "function rKWZYMWxANufFHXq(zjEXOnENJc,BCFNeJPcyIePZluJB,atqXSFfsNzMgIeYHBYYD){return String.fromCharCode(zjEXOnENJc,BCFNeJPcyIePZ" ascii
    $s18 = "function ddwivveWzOqQDWRRqr(SqymbdrftDuHuKwMjR,LwIZYmsHpHSSTOWrcQhNHD){return SqymbdrftDuHuKwMjR.indexOf(LwIZYmsHpHSSTOWrcQhNHD)" ascii
    $s19 = "xff;aZkFpsevyYLPRy = srTeYhDGYLfWTlcHeRzoe & 0xff;if (KzsjAO == 64) KHyJwwglLkCGLyA += s(NawtFRtWXUdmGvqUgpwT);else if (yNfbHyeK" ascii
    $s20 = "function s(FWxPPsDMLHFlJWAL){return String.fromCharCode(FWxPPsDMLHFlJWAL);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}