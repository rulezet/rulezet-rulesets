rule sig_20160531_0cb9cc61517f3ec080376b7e8e3ea367 {
  meta:
    description = "datamaliciousorder - file 20160531_0cb9cc61517f3ec080376b7e8e3ea367.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1045b6275d9d7c95f76bedda2a29dc96c4c9d2671de1b23fa02bcde619db7a22"

  strings:
    $s1  = "function HcFVwyfXFgsGSFZGXJ(ZYvtLrmqm,PrjAny){return ZYvtLrmqm.charAt(PrjAny);}" fullword ascii
    $s2  = "var ROYxugOntQYMCE=function(){return WScript.CreateObject(EVWPRMcjFcai[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = ");return oKSghZqLzIlImgOOKkvBYCID;}" fullword ascii
    $s4  = "function NHGjcfCiQartIsEy(MIomIYQRGqgl,RoMnXtykuJKg){return MIomIYQRGqgl.indexOf(RoMnXtykuJKg);}" fullword ascii
    $s5  = "lse oKSghZqLzIlImgOOKkvBYCID += pKMtl(Oxycc, HhZjsyqaqTO, VTAzpOUyOhFjedyN);} while (MYKUwLkkJQhkppcDuLoj < SPngfeOeePQof.length" ascii
    $s6  = "(gUWeTSs,0x1,0x0)}function yXbmzxuOsv(uKQNgyOh,MZuFNAfX,DenBhuZis){var wigBoJZUq=uKQNgyOh.createtextfile(MZuFNAfX,true);wigBoJZU" ascii
    $s7  = "=0;aqneJZIllL<MmNqSsMAvpiOf.length;aqneJZIllL++) {jfFDgFPwzZYN+=huGJiK[MmNqSsMAvpiOf[aqneJZIllL]];}return jfFDgFPwzZYN.substring" ascii
    $s8  = "(gUWeTSs,0x1,0x0)}function yXbmzxuOsv(uKQNgyOh,MZuFNAfX,DenBhuZis){var wigBoJZUq=uKQNgyOh.createtextfile(MZuFNAfX,true);wigBoJZU" ascii
    $s9  = "function Lx(yaeZSYfg){return String.fromCharCode(yaeZSYfg);}" fullword ascii
    $s10 = " 64) oKSghZqLzIlImgOOKkvBYCID += Lx(Oxycc);else if (qNKSSYgyqvL == 64) oKSghZqLzIlImgOOKkvBYCID += DCzbqfu(Oxycc, HhZjsyqaqTO);e" ascii
    $s11 = "function GexmeL(){return ROYxugOntQYMCE.ExpandEnvironmentStrings(hsVtEHiWFduwYb())}" fullword ascii
    $s12 = "function pKMtl(makaJSyrUdsT,MzGwPR,xlJWefkqJdpxoPujl){return String.fromCharCode(makaJSyrUdsT,MzGwPR,xlJWefkqJdpxoPujl);}" fullword ascii
    $s13 = "function hsVtEHiWFduwYb(){return cMDtXl(EVWPRMcjFcai[9],[1,5,7],EVWPRMcjFcai[10]);}" fullword ascii
    $s14 = "function cMDtXl(ekyOB,MmNqSsMAvpiOf,huJquGyPpBkh){huGJiK=ekyOB.split(huJquGyPpBkh);jfFDgFPwzZYN = EVWPRMcjFcai[0];for(aqneJZIllL" ascii
    $s15 = "function PxNykCTtMneiV(){return cMDtXl(EVWPRMcjFcai[11],[2,4,8,10],EVWPRMcjFcai[12]);}" fullword ascii
    $s16 = "function cMDtXl(ekyOB,MmNqSsMAvpiOf,huJquGyPpBkh){huGJiK=ekyOB.split(huJquGyPpBkh);jfFDgFPwzZYN = EVWPRMcjFcai[0];for(aqneJZIllL" ascii
    $s17 = "function zJLlZawSQNllQG(){return cMDtXl(EVWPRMcjFcai[13],[0,3,6],EVWPRMcjFcai[14]);}" fullword ascii
    $s18 = "function utsRqrUBCo(SPngfeOeePQof) {var HlzgYrDaIYBsfM = yPOaTgu.join(EVWPRMcjFcai[7]);var Oxycc, HhZjsyqaqTO, VTAzpOUyOhFjedyN," ascii
    $s19 = "function DCzbqfu(ffeCAxvCuqVwJc,vqSbUHjmwHNiNQghfput){return String.fromCharCode(ffeCAxvCuqVwJc,vqSbUHjmwHNiNQghfput);}" fullword ascii
    $s20 = "var Lrguh=function(){return new ActiveXObject(EVWPRMcjFcai[1]);}();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}