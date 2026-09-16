rule sig_20151211_143b34a2917bc86fcc896ebe75053861 {
  meta:
    description = "datamaliciousorder - file 20151211_143b34a2917bc86fcc896ebe75053861.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fd5784116203c382abf2af729bcd165d04f80a797fe13493c34e19e0b2bbe70"

  strings:
    $s1  = "function dxZvpUg(TkZAFmiFLjQjgVBBjEywgrjdFhwBrzpQIcOF) {return !isNaN(parseFloat(TkZAFmiFLjQjgVBBjEywgrjdFhwBrzpQIcOF)) && isFin" ascii
    $s2  = "function dxZvpUg(TkZAFmiFLjQjgVBBjEywgrjdFhwBrzpQIcOF) {return !isNaN(parseFloat(TkZAFmiFLjQjgVBBjEywgrjdFhwBrzpQIcOF)) && isFin" ascii
    $s3  = "var B=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"54\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function uKmxARuolUlIATIhzQINxPPnDiapYQIGJHjdELmUOfwXPSsHEDbDfy(tPZqRllKcuyHI,FfGDJvaUcNvtbq){ return pdBPE[SuWER(tPZqRllKcuyHI[" ascii
    $s5  = "function lYnsIHkhBRg(wbmcBsZI,EjzNBa){return wbmcBsZI.split(EjzNBa)}" fullword ascii
    $s6  = "function CXJCddCZDakJzeKRe(LopAH){ZiSmEelEQBN= '';EfvKMZOjTaR=(-167+167)/215; while(true){if(EfvKMZOjTaR >= (-680+988)/154)break" ascii
    $s7  = " UIzwr;}function RAsAnXyKrxGdoPu(uNwumHlUqPzhfYURK){eval(uNwumHlUqPzhfYURK)}" fullword ascii
    $s8  = "var B=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"54\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "function CXJCddCZDakJzeKRe(LopAH){ZiSmEelEQBN= '';EfvKMZOjTaR=(-167+167)/215; while(true){if(EfvKMZOjTaR >= (-680+988)/154)break" ascii
    $s10 = "function SuWER(iQnLnvKtXJI,lBjnmaqwGoafS,jVAGcqbK){HFnf=parseInt(iQnLnvKtXJI,lBjnmaqwGoafS);UIzwr=HFnf.toString(jVAGcqbK);return" ascii
    $s11 = "function uKmxARuolUlIATIhzQINxPPnDiapYQIGJHjdELmUOfwXPSsHEDbDfy(tPZqRllKcuyHI,FfGDJvaUcNvtbq){ return pdBPE[SuWER(tPZqRllKcuyHI[" ascii
    $s12 = "function SuWER(iQnLnvKtXJI,lBjnmaqwGoafS,jVAGcqbK){HFnf=parseInt(iQnLnvKtXJI,lBjnmaqwGoafS);UIzwr=HFnf.toString(jVAGcqbK);return" ascii
    $s13 = ";hRQMjMNFP[EfvKMZOjTaR]=(-665+665)/435; while(true) { if(hRQMjMNFP[EfvKMZOjTaR] > LopAH[EfvKMZOjTaR].length-(-788+894)/106) { br" ascii
    $s14 = "]++;}EfvKMZOjTaR++;} return ZiSmEelEQBN}" fullword ascii
    $s15 = "var E=new Array(\"27\",\"28\",\"28\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s16 = "var E=new Array(\"27\",\"28\",\"28\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}