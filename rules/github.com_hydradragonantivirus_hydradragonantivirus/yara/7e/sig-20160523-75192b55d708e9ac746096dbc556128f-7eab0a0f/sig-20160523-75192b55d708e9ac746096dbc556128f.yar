rule sig_20160523_75192b55d708e9ac746096dbc556128f {
  meta:
    description = "datamaliciousorder - file 20160523_75192b55d708e9ac746096dbc556128f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1a962f44a05533b6bf0830e88b5518c4f5a9cfcb179aa84dc869ee796e913c3"

  strings:
    $s1  = "function wNOhQzDgng(dmXzodHX,GLArePqZitnN) {dmXzodHX.Run(GLArePqZitnN, 0x1, 0x0);}" fullword ascii
    $s2  = "function wIkMaOiR(tuvlU) {var ZcgvAHnn=iPJMMeSwwOJErudQigUrJOO[13];for(var wqRoM=0;wqRoM<tuvlU;wqRoM++){IFQTM+=ZcgvAHnn.charAt(M" ascii
    $s3  = "function wIkMaOiR(tuvlU) {var ZcgvAHnn=iPJMMeSwwOJErudQigUrJOO[13];for(var wqRoM=0;wqRoM<tuvlU;wqRoM++){IFQTM+=ZcgvAHnn.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*ZcgvAHnn.length));}return IFQTM;}" fullword ascii
    $s5  = "function RaABufY(JsElk) {JsElk.close();}" fullword ascii
    $s6  = "function SSKxL(GkxTvzmI,HHcYr,oEeVzeUtSn){QTNs(GkxTvzmI);wJWTjick(GkxTvzmI);ykxjsMF(GkxTvzmI,HHcYr);gwGUUVffn(GkxTvzmI);ZMDS(Gkx" ascii
    $s7  = "function QTNs(bdKKmb) {bdKKmb.open();}" fullword ascii
    $s8  = "function Liyp(voWXqi,sxnPpyF){IUok = iPJMMeSwwOJErudQigUrJOO[10].split(iPJMMeSwwOJErudQigUrJOO[11]);sxnPpyF.open(IUok[0]+IUok[2]" ascii
    $s9  = "function wJWTjick(HydeeyYhj) {HydeeyYhj.type=1;}" fullword ascii
    $s10 = "function Liyp(voWXqi,sxnPpyF){IUok = iPJMMeSwwOJErudQigUrJOO[10].split(iPJMMeSwwOJErudQigUrJOO[11]);sxnPpyF.open(IUok[0]+IUok[2]" ascii
    $s11 = "function aULGUUq(){return Math.random();}" fullword ascii
    $s12 = "function ykxjsMF(OxdK,kEhsi) {OxdK.write(kEhsi);}" fullword ascii
    $s13 = "function ZMDS(VcNWQMz,aIvwvUh) {VcNWQMz.saveToFile(aIvwvUh, 2);}" fullword ascii
    $s14 = "function qSUbU(fBOKfR){return new ActiveXObject(fBOKfR);}" fullword ascii
    $s15 = "function bPnSwFe() {var FBQB=100000;var ocQdWl = 100;return aULGUUq()*(FBQB-ocQdWl)+ocQdWl;}" fullword ascii
    $s16 = "function gwGUUVffn(cWbcPH) {var sFHtrOCLIV=[];cWbcPH.position=sFHtrOCLIV.length*(5013143-846);}" fullword ascii
    $s17 = "+IUok[3], voWXqi, false);sxnPpyF.send();}" fullword ascii
    $s18 = "function mAjqAB(fBOKfR){return fBOKfR.ExpandEnvironmentStrings(iPJMMeSwwOJErudQigUrJOO[9])}" fullword ascii
    $s19 = "if(PzYw>lfEfw.length) break;" fullword ascii
    $s20 = "function SSKxL(GkxTvzmI,HHcYr,oEeVzeUtSn){QTNs(GkxTvzmI);wJWTjick(GkxTvzmI);ykxjsMF(GkxTvzmI,HHcYr);gwGUUVffn(GkxTvzmI);ZMDS(Gkx" ascii

  condition:
    uint16(0) == 0x1d27 and
    8 of them
}