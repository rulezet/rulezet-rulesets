rule sig_20151217_a95bd64dc1668bc8492745b429d753a3 {
  meta:
    description = "datamaliciousorder - file 20151217_a95bd64dc1668bc8492745b429d753a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12a74a5828705dff6be6881f15f33a9dc9d0591f77221ab333888b1f3f9b7c52"

  strings:
    $s1  = "ath.cos(875), 2) - 1)));} uolDphlsJ[XPtzaKbbolW]++;}XPtzaKbbolW++;} return CVdcMsAvzpn}" fullword ascii
    $s2  = "h.pow(Math.cos(47), 2) - 1)); while(true) { if(uolDphlsJ[XPtzaKbbolW] > iTupr[XPtzaKbbolW].length-(-81+83)/2) { break; } if (Pba" ascii
    $s3  = "function XhPvXQAnvIPMmbMVA(iTupr){CVdcMsAvzpn= '';XPtzaKbbolW=Math.round((Math.pow(Math.sin(221), 2) + Math.pow(Math.cos(221), 2" ascii
    $s4  = ") - 1));while(true){if (XPtzaKbbolW >= (1196+262)/243){break;}uolDphlsJ[XPtzaKbbolW]=Math.round((Math.pow(Math.sin(47), 2) + Mat" ascii
    $s5  = "function XhPvXQAnvIPMmbMVA(iTupr){CVdcMsAvzpn= '';XPtzaKbbolW=Math.round((Math.pow(Math.sin(221), 2) + Math.pow(Math.cos(221), 2" ascii
    $s6  = "function PbaxSkU(sRVYTfQMNqcfGaAojVPwdMoBzlgWqVnAvAIQ) {return !lCvSNmloedu(TcqtUPRTQHqlMqU(sRVYTfQMNqcfGaAojVPwdMoBzlgWqVnAvAIQ" ascii
    $s7  = "function qPaXMfjWIUxzbso(OVYMiUQRpAVqPZVJY,CEMPFKFNgXzYTqLDjpFLgwbtWfyDhozlVO,CmDXmBLjMkClCwqUtBZxyGwjwpqbYvlefip){eval(OVYMiUQR" ascii
    $s8  = "function qPaXMfjWIUxzbso(OVYMiUQRpAVqPZVJY,CEMPFKFNgXzYTqLDjpFLgwbtWfyDhozlVO,CmDXmBLjMkClCwqUtBZxyGwjwpqbYvlefip){eval(OVYMiUQR" ascii
    $s9  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s10 = "function WSvkN(QEfbERNMLGO,AkIkDdFAhEXpi,qNrchFBT){syTX=wbPtTEHVVlZrMJxsj(QEfbERNMLGO,AkIkDdFAhEXpi);ibJwC=syTX.toString(qNrchFB" ascii
    $s11 = "function PbaxSkU(sRVYTfQMNqcfGaAojVPwdMoBzlgWqVnAvAIQ) {return !lCvSNmloedu(TcqtUPRTQHqlMqU(sRVYTfQMNqcfGaAojVPwdMoBzlgWqVnAvAIQ" ascii
    $s12 = "function egfrVKKcnhPl(NMKMBJcJQbeSv) {return isFinite(NMKMBJcJQbeSv);}" fullword ascii
    $s13 = "function z(mlaxAdriLUsATP,ycbAtgVtWzlPN,sPfofVWxoZI) {mlaxAdriLUsATP[ycbAtgVtWzlPN]=sPfofVWxoZI;}" fullword ascii
    $s14 = "function T(rYcIlNGVilFw,NgpqZcdeabOPfR){rYcIlNGVilFw.push(NgpqZcdeabOPfR);}" fullword ascii
    $s15 = "function wbPtTEHVVlZrMJxsj(HyCoTtmgRr,efokOqhenq) {return parseInt(HyCoTtmgRr,efokOqhenq);}" fullword ascii
    $s16 = "function DIpZuyGIuFIpGJtNypNKMMKJmjZWGbSJsvHdhGXOUFnVrQGAQmgBrP(GPGlzHMBlacBe,TWLVgjhwjhntDp){ return lHFGBZN[rxodEWXp[WSvkN(GPG" ascii
    $s17 = "function lCvSNmloedu(zwVlFKgbkIcWvQ) {return isNaN(zwVlFKgbkIcWvQ);}" fullword ascii
    $s18 = "function DIpZuyGIuFIpGJtNypNKMMKJmjZWGbSJsvHdhGXOUFnVrQGAQmgBrP(GPGlzHMBlacBe,TWLVgjhwjhntDp){ return lHFGBZN[rxodEWXp[WSvkN(GPG" ascii
    $s19 = "T);return ibJwC;}" fullword ascii
    $s20 = "function TcqtUPRTQHqlMqU(DffrVYhtbYObRRZbXEi) {return parseFloat(DffrVYhtbYObRRZbXEi);}" fullword ascii

  condition:
    uint16(0) == 0x7872 and
    8 of them
}