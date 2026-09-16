rule sig_20151217_6673aa7e02ff247db4a24155cd7bcccb {
  meta:
    description = "datamaliciousorder - file 20151217_6673aa7e02ff247db4a24155cd7bcccb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83b1d022f0e4e454f53e3708740350a3df0f76508814ea0dc5b9ae821741313"

  strings:
    $s1  = "ath.cos(93), 2) - 1)));} NcAEesIQf[ymfWZaxLmiM]++;}ymfWZaxLmiM++;} return AeLUlywwsAO}" fullword ascii
    $s2  = "function sHiIxoiYODpPOYpMS(cqOAj){AeLUlywwsAO= '';ymfWZaxLmiM=Math.round((Math.pow(Math.sin(19), 2) + Math.pow(Math.cos(19), 2) " ascii
    $s3  = "pow(Math.cos(472), 2) - 1)); while(true) { if(NcAEesIQf[ymfWZaxLmiM] > cqOAj[ymfWZaxLmiM].length-(138+32)/170) { break; } if (hG" ascii
    $s4  = "function sHiIxoiYODpPOYpMS(cqOAj){AeLUlywwsAO= '';ymfWZaxLmiM=Math.round((Math.pow(Math.sin(19), 2) + Math.pow(Math.cos(19), 2) " ascii
    $s5  = "function hGHGSDA(WJqCZifeSpzJHbWLPFEdLoRrYDCcvIiOQzNO) {return !dgZLEeoiYvx(bGANkDCLyfuvjZF(WJqCZifeSpzJHbWLPFEdLoRrYDCcvIiOQzNO" ascii
    $s6  = "- 1));while(true){if (ymfWZaxLmiM >= (3178+14)/532){break;}NcAEesIQf[ymfWZaxLmiM]=Math.round((Math.pow(Math.sin(472), 2) + Math." ascii
    $s7  = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s8  = "function WQccndWxFpnYpwjsyhoxtrwCxUgNHLxoUBkoQbHXcryBlDteGvlazL(kAHpXTkHgSHbH,MQUFVNJIyBevCF){ return jrZigTV[LsULRoAS[ynjcx(kAH" ascii
    $s9  = "function WQccndWxFpnYpwjsyhoxtrwCxUgNHLxoUBkoQbHXcryBlDteGvlazL(kAHpXTkHgSHbH,MQUFVNJIyBevCF){ return jrZigTV[LsULRoAS[ynjcx(kAH" ascii
    $s10 = "function hGHGSDA(WJqCZifeSpzJHbWLPFEdLoRrYDCcvIiOQzNO) {return !dgZLEeoiYvx(bGANkDCLyfuvjZF(WJqCZifeSpzJHbWLPFEdLoRrYDCcvIiOQzNO" ascii
    $s11 = "function s(dDYgFbgkKozf,HSAwPfzpaORKhz){dDYgFbgkKozf.push(HSAwPfzpaORKhz);}" fullword ascii
    $s12 = "function IDOxGzAsaRWD(JLuRwFXHjFPdY) {return isFinite(JLuRwFXHjFPdY);}" fullword ascii
    $s13 = "function dgZLEeoiYvx(uYHQuRFSaHbAal) {return isNaN(uYHQuRFSaHbAal);}" fullword ascii
    $s14 = "r);return nXOxI;}" fullword ascii
    $s15 = "function ynjcx(bmChyhIWvbq,vIwldkoDRSGSl,RIOpIjmr){JKyq=gBgkVkaSVhEjHfHfl(bmChyhIWvbq,vIwldkoDRSGSl);nXOxI=JKyq.toString(RIOpIjm" ascii
    $s16 = "function ynjcx(bmChyhIWvbq,vIwldkoDRSGSl,RIOpIjmr){JKyq=gBgkVkaSVhEjHfHfl(bmChyhIWvbq,vIwldkoDRSGSl);nXOxI=JKyq.toString(RIOpIjm" ascii
    $s17 = "function gBgkVkaSVhEjHfHfl(xvGfpaRXUr,RgPphQxuay) {return parseInt(xvGfpaRXUr,RgPphQxuay);}" fullword ascii
    $s18 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s19 = "function E(aRbUJMWrVSjseN,rWfPJVRyXEhxV,deAuMfqYUvE) {aRbUJMWrVSjseN[rWfPJVRyXEhxV]=deAuMfqYUvE;}" fullword ascii
    $s20 = "function bGANkDCLyfuvjZF(kSYvWGMhJVTjsQkRbgW) {return parseFloat(kSYvWGMhJVTjsQkRbgW);}" fullword ascii

  condition:
    uint16(0) == 0x734c and
    8 of them
}