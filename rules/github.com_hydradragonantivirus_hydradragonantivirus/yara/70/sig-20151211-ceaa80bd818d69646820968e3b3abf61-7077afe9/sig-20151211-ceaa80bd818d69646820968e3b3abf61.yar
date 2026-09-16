rule sig_20151211_ceaa80bd818d69646820968e3b3abf61 {
  meta:
    description = "datamaliciousorder - file 20151211_ceaa80bd818d69646820968e3b3abf61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8dfc97f4f638268aef3d794bd79c876995aafdd5a0a17c8e3cb9275e43bb2d1"

  strings:
    $s1  = "function UKnMLKk(jUmyMYUXiwgsBXrkKcppejPxfnBbGBUznRfJ) {return !isNaN(parseFloat(jUmyMYUXiwgsBXrkKcppejPxfnBbGBUznRfJ)) && isFin" ascii
    $s2  = "function UKnMLKk(jUmyMYUXiwgsBXrkKcppejPxfnBbGBUznRfJ) {return !isNaN(parseFloat(jUmyMYUXiwgsBXrkKcppejPxfnBbGBUznRfJ)) && isFin" ascii
    $s3  = "var P=new Array(\"29\",\"26\",\"2a\",\"2f\",\"29\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s4  = "function WMVWqHqLtqEGAqNWCBuQCBBgGqziKcJGNIODcUdoOABOPQQAAmdybR(jnwapHfffWcik,ybLaPiHnujbUzb){ return FeFfN[wWVfe(jnwapHfffWcik[" ascii
    $s5  = ";WBXvSfWfm[FhicGRJlMkj]=(-949+949)/916; while(true) { if(WBXvSfWfm[FhicGRJlMkj] > IsDKa[FhicGRJlMkj].length-(164+235)/399) { bre" ascii
    $s6  = "function VTHxrrTEtrHxICgro(IsDKa){rVzFboqHdHr= '';FhicGRJlMkj=(-456+456)/953; while(true){if(FhicGRJlMkj >= (1285+519)/902)break" ascii
    $s7  = "]++;}FhicGRJlMkj++;} return rVzFboqHdHr}" fullword ascii
    $s8  = "function VTHxrrTEtrHxICgro(IsDKa){rVzFboqHdHr= '';FhicGRJlMkj=(-456+456)/953; while(true){if(FhicGRJlMkj >= (1285+519)/902)break" ascii
    $s9  = "function iBZxjFuZHjL(FwTqcbbb,puyxFt){return FwTqcbbb.split(puyxFt)}" fullword ascii
    $s10 = "function WMVWqHqLtqEGAqNWCBuQCBBgGqziKcJGNIODcUdoOABOPQQAAmdybR(jnwapHfffWcik,ybLaPiHnujbUzb){ return FeFfN[wWVfe(jnwapHfffWcik[" ascii
    $s11 = "function wWVfe(lNZyzVUSUiA,mLQnCZkQjSIDQ,spzzZYYy){izND=parseInt(lNZyzVUSUiA,mLQnCZkQjSIDQ);dmcrO=izND.toString(spzzZYYy);return" ascii
    $s12 = "var P=new Array(\"29\",\"26\",\"2a\",\"2f\",\"29\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function wWVfe(lNZyzVUSUiA,mLQnCZkQjSIDQ,spzzZYYy){izND=parseInt(lNZyzVUSUiA,mLQnCZkQjSIDQ);dmcrO=izND.toString(spzzZYYy);return" ascii
    $s16 = " dmcrO;}function VdGPYtsXmitADOQ(DqqktAcaXfygSknKL){eval(DqqktAcaXfygSknKL)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}