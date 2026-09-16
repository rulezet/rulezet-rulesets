rule sig_20151211_3fad7597a70e040a87dfb7101ba27923 {
  meta:
    description = "datamaliciousorder - file 20151211_3fad7597a70e040a87dfb7101ba27923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "550c131c696f998981bd2b762e360413e117e47662b6f378cc7e979d31d3b2fa"

  strings:
    $s1  = "function edpNYce(hffbIUqVxeNrEAaesbhgJzcZupivXurQilFM) {return !isNaN(parseFloat(hffbIUqVxeNrEAaesbhgJzcZupivXurQilFM)) && isFin" ascii
    $s2  = "function edpNYce(hffbIUqVxeNrEAaesbhgJzcZupivXurQilFM) {return !isNaN(parseFloat(hffbIUqVxeNrEAaesbhgJzcZupivXurQilFM)) && isFin" ascii
    $s3  = "function ytSIddoSzCy(yOMEAdrW,rkVuBL){return yOMEAdrW.split(rkVuBL)}" fullword ascii
    $s4  = "function bWIqCSutAjnfnsxfK(gnGnk){nEmcbjByqvg= '';dOXzdYEXWRi=(-811+811)/365; while(true){if(dOXzdYEXWRi >= (1186+652)/919)break" ascii
    $s5  = "var g=new Array(\"28\",\"2d\",\"2e\",\"26\",\"2f\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = ";ABYlZiSdc[dOXzdYEXWRi]=(-36+36)/567; while(true) { if(ABYlZiSdc[dOXzdYEXWRi] > gnGnk[dOXzdYEXWRi].length-(546+239)/785) { break" ascii
    $s7  = "var g=new Array(\"28\",\"2d\",\"2e\",\"26\",\"2f\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "function lAnDesLtyidlgkTphzZLWyhtjzJHtUHTYNiHxlCzuNiegHJMyENxxs(UKloEdgnzjCOG,tdcLcBPjRRndyc){ return MQKQb[iUjMB(UKloEdgnzjCOG[" ascii
    $s9  = "function lAnDesLtyidlgkTphzZLWyhtjzJHtUHTYNiHxlCzuNiegHJMyENxxs(UKloEdgnzjCOG,tdcLcBPjRRndyc){ return MQKQb[iUjMB(UKloEdgnzjCOG[" ascii
    $s10 = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function iUjMB(lleqNptjHVV,JBBAryvcUhrEG,cHUFUZCw){zxhH=parseInt(lleqNptjHVV,JBBAryvcUhrEG);xARzo=zxhH.toString(cHUFUZCw);return" ascii
    $s12 = "function iUjMB(lleqNptjHVV,JBBAryvcUhrEG,cHUFUZCw){zxhH=parseInt(lleqNptjHVV,JBBAryvcUhrEG);xARzo=zxhH.toString(cHUFUZCw);return" ascii
    $s13 = "function bWIqCSutAjnfnsxfK(gnGnk){nEmcbjByqvg= '';dOXzdYEXWRi=(-811+811)/365; while(true){if(dOXzdYEXWRi >= (1186+652)/919)break" ascii
    $s14 = "++;}dOXzdYEXWRi++;} return nEmcbjByqvg}" fullword ascii
    $s15 = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = " xARzo;}function dJrbqnGakdiYLgS(AHXnsetnXoPeaEfXs){eval(AHXnsetnXoPeaEfXs)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}