rule sig_20151210_4a5916d56b89499da127fa600b8bc93d {
  meta:
    description = "datamaliciousorder - file 20151210_4a5916d56b89499da127fa600b8bc93d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a512c1a75bcac08c8895ed28eedf890f407cbd5872488891df18533bd25389b8"

  strings:
    $s1  = "function jbVPccw(GWcDypVhKpZsqBAKlJIwoOtFLSkdpnAOyYsl) {return !isNaN(parseFloat(GWcDypVhKpZsqBAKlJIwoOtFLSkdpnAOyYsl)) && isFin" ascii
    $s2  = "function jbVPccw(GWcDypVhKpZsqBAKlJIwoOtFLSkdpnAOyYsl) {return !isNaN(parseFloat(GWcDypVhKpZsqBAKlJIwoOtFLSkdpnAOyYsl)) && isFin" ascii
    $s3  = " GLLkG;}function FcKBasVaBPLBUfE(oNgwCrhfQKTqHvlec){eval(oNgwCrhfQKTqHvlec)}" fullword ascii
    $s4  = "]++;}} return zTXPKikOzpv}" fullword ascii
    $s5  = "HlLYuphIn[QJjMjJXAkoX]=(-838+838)/990; while(true) { if(HlLYuphIn[QJjMjJXAkoX] > DXgFl[QJjMjJXAkoX].length-(-124+565)/441) { bre" ascii
    $s6  = "function JUdWt(nuOnRkOJgRE,YTVtwIoNhaaHs,KBaSrNtv){LPgx=parseInt(nuOnRkOJgRE,YTVtwIoNhaaHs);GLLkG=LPgx.toString(KBaSrNtv);return" ascii
    $s7  = "function JUdWt(nuOnRkOJgRE,YTVtwIoNhaaHs,KBaSrNtv){LPgx=parseInt(nuOnRkOJgRE,YTVtwIoNhaaHs);GLLkG=LPgx.toString(KBaSrNtv);return" ascii
    $s8  = "function SludUgMJIFF(zuwCPvvt,dzsEvW){return zuwCPvvt.split(dzsEvW)}" fullword ascii
    $s9  = "function feiKFOcsnvzhAXGRJ(DXgFl){zTXPKikOzpv= '';for(QJjMjJXAkoX=(-492+492)/597; QJjMjJXAkoX < (1202+188)/695; QJjMjJXAkoX++) {" ascii
    $s10 = "function NPUplBrKuUmWwSMrwpKIMTxEIZzyqsuYeMHZCAQyAmjtbiEslhlKMG(oVQIgIzdnkJKC,OmKGBGTjoYTiPw){ return mNcCx[JUdWt(oVQIgIzdnkJKC[" ascii
    $s11 = "function feiKFOcsnvzhAXGRJ(DXgFl){zTXPKikOzpv= '';for(QJjMjJXAkoX=(-492+492)/597; QJjMjJXAkoX < (1202+188)/695; QJjMjJXAkoX++) {" ascii
    $s12 = "function NPUplBrKuUmWwSMrwpKIMTxEIZzyqsuYeMHZCAQyAmjtbiEslhlKMG(oVQIgIzdnkJKC,OmKGBGTjoYTiPw){ return mNcCx[JUdWt(oVQIgIzdnkJKC[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}