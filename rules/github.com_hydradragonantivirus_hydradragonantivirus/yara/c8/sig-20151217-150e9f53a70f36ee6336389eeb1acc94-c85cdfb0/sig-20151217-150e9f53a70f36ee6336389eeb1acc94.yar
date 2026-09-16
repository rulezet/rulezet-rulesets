rule sig_20151217_150e9f53a70f36ee6336389eeb1acc94 {
  meta:
    description = "datamaliciousorder - file 20151217_150e9f53a70f36ee6336389eeb1acc94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13466bc21d46c7f5cc503868d2492be9c36da4f7949820cdb146614bbbc79e81"

  strings:
    $s1  = "Math.cos(700), 2) - 1)));} SNktMRDrb[nAWrhfXsMFz]++;}nAWrhfXsMFz++;} return sRltKHiYKHI}" fullword ascii
    $s2  = "function wzghrUfsXDyOtXIhu(eYUaz){sRltKHiYKHI= '';nAWrhfXsMFz=Math.round((Math.pow(Math.sin(6), 2) + Math.pow(Math.cos(6), 2) - " ascii
    $s3  = "function wzghrUfsXDyOtXIhu(eYUaz){sRltKHiYKHI= '';nAWrhfXsMFz=Math.round((Math.pow(Math.sin(6), 2) + Math.pow(Math.cos(6), 2) - " ascii
    $s4  = "ow(Math.cos(690), 2) - 1)); while(true) { if(SNktMRDrb[nAWrhfXsMFz] > eYUaz[nAWrhfXsMFz].length-(-803+862)/59) { break; } if (vP" ascii
    $s5  = "1));while(true){if (nAWrhfXsMFz >= (3426+918)/724){break;}SNktMRDrb[nAWrhfXsMFz]=Math.round((Math.pow(Math.sin(690), 2) + Math.p" ascii
    $s6  = "function vPNBJhB(rQZrqzcfEHnGegmTvKCjQrEdEgevrwTeJSic) {return !UQnWUxkQlEw(qTIZTIZQqagbFhV(rQZrqzcfEHnGegmTvKCjQrEdEgevrwTeJSic" ascii
    $s7  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s8  = "function qTIZTIZQqagbFhV(vYgxihsdNoKxXuNxzpw) {return parseFloat(vYgxihsdNoKxXuNxzpw);}" fullword ascii
    $s9  = "function n(txkIEJQCPiUIQn,WRjtzXbmyPuRX,pWZIjLbpmQa) {txkIEJQCPiUIQn[WRjtzXbmyPuRX]=pWZIjLbpmQa;}" fullword ascii
    $s10 = "function UQnWUxkQlEw(OVIFGClEqibzWR) {return isNaN(OVIFGClEqibzWR);}" fullword ascii
    $s11 = "function jPUiNlIwvPhKuAC(PvEyXpRFkwZqSwRwy,gMxQHkjenOfKeKkHJyDkmtmtzpGccSTowz,gBggkimOWnrQbsTqEGzAgXHTtDolUQDRggP){eval(PvEyXpRF" ascii
    $s12 = "X);return JRODX;}" fullword ascii
    $s13 = "function eJVGM(xZHGZwEDiXn,RjTklPeySYnga,PkLOBOZX){MdIy=xZWGMUaVcrfLkgUVS(xZHGZwEDiXn,RjTklPeySYnga);JRODX=MdIy.toString(PkLOBOZ" ascii
    $s14 = "function RUsDRPcpoTbIdDDfDDzMomhXwdUXscOwCuGsyuconSpgdqkckPcgRE(gqLVPhCtYjAwC,dGeBRfLIEIOKOj){ return BUOBfaP[WfauujFP[eJVGM(gqL" ascii
    $s15 = "function dSUGiAlafWIa(OBaRVZxKXkveD) {return isFinite(OBaRVZxKXkveD);}" fullword ascii
    $s16 = "function vPNBJhB(rQZrqzcfEHnGegmTvKCjQrEdEgevrwTeJSic) {return !UQnWUxkQlEw(qTIZTIZQqagbFhV(rQZrqzcfEHnGegmTvKCjQrEdEgevrwTeJSic" ascii
    $s17 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s18 = "function RUsDRPcpoTbIdDDfDDzMomhXwdUXscOwCuGsyuconSpgdqkckPcgRE(gqLVPhCtYjAwC,dGeBRfLIEIOKOj){ return BUOBfaP[WfauujFP[eJVGM(gqL" ascii
    $s19 = "function jPUiNlIwvPhKuAC(PvEyXpRFkwZqSwRwy,gMxQHkjenOfKeKkHJyDkmtmtzpGccSTowz,gBggkimOWnrQbsTqEGzAgXHTtDolUQDRggP){eval(PvEyXpRF" ascii
    $s20 = "function eJVGM(xZHGZwEDiXn,RjTklPeySYnga,PkLOBOZX){MdIy=xZWGMUaVcrfLkgUVS(xZHGZwEDiXn,RjTklPeySYnga);JRODX=MdIy.toString(PkLOBOZ" ascii

  condition:
    uint16(0) == 0x6657 and
    8 of them
}