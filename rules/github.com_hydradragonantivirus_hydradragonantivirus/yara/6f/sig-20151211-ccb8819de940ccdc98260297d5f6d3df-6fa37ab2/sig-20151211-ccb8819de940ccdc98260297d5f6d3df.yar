rule sig_20151211_ccb8819de940ccdc98260297d5f6d3df {
  meta:
    description = "datamaliciousorder - file 20151211_ccb8819de940ccdc98260297d5f6d3df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f1ab7d35175410e63b706454a826059573660e9c27ca1929108b6dc52b454ef"

  strings:
    $s1  = "function aXPvbOn(poGQNuziFgAYxMJWVrUmGDsoycMniYvqTCmf) {return !isNaN(parseFloat(poGQNuziFgAYxMJWVrUmGDsoycMniYvqTCmf)) && isFin" ascii
    $s2  = "function aXPvbOn(poGQNuziFgAYxMJWVrUmGDsoycMniYvqTCmf) {return !isNaN(parseFloat(poGQNuziFgAYxMJWVrUmGDsoycMniYvqTCmf)) && isFin" ascii
    $s3  = " SEhtk;}function oMsgWPrzQDhBAKr(qKwYSKlIIbkbXomAG){eval(qKwYSKlIIbkbXomAG)}" fullword ascii
    $s4  = "ESXMunVxQ[ovwcjFXtTUt]=(-667+667)/459; while(true) { if(ESXMunVxQ[ovwcjFXtTUt] > MMEXL[ovwcjFXtTUt].length-(-360+857)/497) { bre" ascii
    $s5  = "function jYAdx(jdwXHABDsQh,RCROPnuecbSzk,YgqygPsv){QRvm=parseInt(jdwXHABDsQh,RCROPnuecbSzk);SEhtk=QRvm.toString(YgqygPsv);return" ascii
    $s6  = "]++;}ovwcjFXtTUt++;} return GXjQLIkrzPR}" fullword ascii
    $s7  = "function aXMQMpAHpnCNVBwzcMafODjpbtbdjPhxDlFWOJTgVYbvMeljrmdRMe(zFfhzPqsJAbpv,fTqnEuVLqAErFo){ return EFUpp[jYAdx(zFfhzPqsJAbpv[" ascii
    $s8  = "function jYAdx(jdwXHABDsQh,RCROPnuecbSzk,YgqygPsv){QRvm=parseInt(jdwXHABDsQh,RCROPnuecbSzk);SEhtk=QRvm.toString(YgqygPsv);return" ascii
    $s9  = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"59\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "function JLgJMiHpkupETUlol(MMEXL){GXjQLIkrzPR= '';ovwcjFXtTUt=(-639+639)/617; while(true){if(ovwcjFXtTUt >= (1671+11)/841)break;" ascii
    $s11 = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"59\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "var N=new Array(\"2d\",\"2b\",\"2b\",\"29\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function JLgJMiHpkupETUlol(MMEXL){GXjQLIkrzPR= '';ovwcjFXtTUt=(-639+639)/617; while(true){if(ovwcjFXtTUt >= (1671+11)/841)break;" ascii
    $s14 = "var N=new Array(\"2d\",\"2b\",\"2b\",\"29\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s15 = "function aXMQMpAHpnCNVBwzcMafODjpbtbdjPhxDlFWOJTgVYbvMeljrmdRMe(zFfhzPqsJAbpv,fTqnEuVLqAErFo){ return EFUpp[jYAdx(zFfhzPqsJAbpv[" ascii
    $s16 = "function kXgKtmYNhyE(DbPSuSwL,hFLmVD){return DbPSuSwL.split(hFLmVD)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}