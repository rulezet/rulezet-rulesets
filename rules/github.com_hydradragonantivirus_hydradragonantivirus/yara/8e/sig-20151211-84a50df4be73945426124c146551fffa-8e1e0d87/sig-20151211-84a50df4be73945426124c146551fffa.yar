rule sig_20151211_84a50df4be73945426124c146551fffa {
  meta:
    description = "datamaliciousorder - file 20151211_84a50df4be73945426124c146551fffa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9a2ded8b60b8545d1298c326131e7fe6461a394e58fe2926f6f9c66b0e80f1c"

  strings:
    $s1  = "function uHmADEt(DAbtildzhgdXIEGekiLbAPRyLpnjIibOKmgB) {return !isNaN(parseFloat(DAbtildzhgdXIEGekiLbAPRyLpnjIibOKmgB)) && isFin" ascii
    $s2  = "function uHmADEt(DAbtildzhgdXIEGekiLbAPRyLpnjIibOKmgB) {return !isNaN(parseFloat(DAbtildzhgdXIEGekiLbAPRyLpnjIibOKmgB)) && isFin" ascii
    $s3  = "function eWPbVBnStjn(WRhxRKcR,OOxnNJ){return WRhxRKcR.split(OOxnNJ)}" fullword ascii
    $s4  = "var L=new Array(\"2e\",\"27\",\"29\",\"2b\",\"27\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "lORdoaZZp[CxCxpgipoNh]=(-675+675)/375; while(true) { if(lORdoaZZp[CxCxpgipoNh] > DGwSP[CxCxpgipoNh].length-(696+68)/764) { break" ascii
    $s6  = "function DZGqMEozjuIIfSaWO(DGwSP){jnexuHnORBw= '';CxCxpgipoNh=(-523+523)/644; while(true){if(CxCxpgipoNh >= (536+524)/530)break;" ascii
    $s7  = "var Q=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = " szlLB;}function aAhWeINKMxoGIQm(RugCwRornbLoYRSZi){eval(RugCwRornbLoYRSZi)}" fullword ascii
    $s9  = "function NlUYQ(ajYsLNlrwBp,kvFsmpTGezbYz,vKsPBqBu){Gddc=parseInt(ajYsLNlrwBp,kvFsmpTGezbYz);szlLB=Gddc.toString(vKsPBqBu);return" ascii
    $s10 = "+;}CxCxpgipoNh++;} return jnexuHnORBw}" fullword ascii
    $s11 = "var L=new Array(\"2e\",\"27\",\"29\",\"2b\",\"27\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = "function bjjZMJzhOUFkbWlDVDpTNSAVPikMoAnoPoeEqbYXdOAhLBpuvhWrxM(HrKJHfrXTETja,fQnAXtmhnPJZmQ){ return xFmAT[NlUYQ(HrKJHfrXTETja[" ascii
    $s13 = "function bjjZMJzhOUFkbWlDVDpTNSAVPikMoAnoPoeEqbYXdOAhLBpuvhWrxM(HrKJHfrXTETja,fQnAXtmhnPJZmQ){ return xFmAT[NlUYQ(HrKJHfrXTETja[" ascii
    $s14 = "function DZGqMEozjuIIfSaWO(DGwSP){jnexuHnORBw= '';CxCxpgipoNh=(-523+523)/644; while(true){if(CxCxpgipoNh >= (536+524)/530)break;" ascii
    $s15 = "var Q=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "function NlUYQ(ajYsLNlrwBp,kvFsmpTGezbYz,vKsPBqBu){Gddc=parseInt(ajYsLNlrwBp,kvFsmpTGezbYz);szlLB=Gddc.toString(vKsPBqBu);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}