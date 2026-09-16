rule sig_20151217_bb0d251ee9f42204b62ffa929f4df315 {
  meta:
    description = "datamaliciousorder - file 20151217_bb0d251ee9f42204b62ffa929f4df315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac8dd729b7938a03c073a3a72430483d189a50dadc7463774f2b42d994f8107b"

  strings:
    $s1  = "pow(Math.cos(332), 2) - 1)));} wRGKTVqbD[aglqDzsSEHN]++;}aglqDzsSEHN++;} return OdywdklIyHz}" fullword ascii
    $s2  = ") - 1));while(true){if (aglqDzsSEHN >= (3367+185)/592){break;}wRGKTVqbD[aglqDzsSEHN]=Math.round((Math.pow(Math.sin(251), 2) + Ma" ascii
    $s3  = "function EkBnkZSPKReSKJvXy(HctCI){OdywdklIyHz= '';aglqDzsSEHN=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s4  = "th.pow(Math.cos(251), 2) - 1)); while(true) { if(wRGKTVqbD[aglqDzsSEHN] > HctCI[aglqDzsSEHN].length-(247+536)/783) { break; } if" ascii
    $s5  = "sPMdyGpxePiqANeoyoSruvLosWFNeKQhTMR([HctCI[aglqDzsSEHN][wRGKTVqbD[aglqDzsSEHN]]], Math.round((Math.pow(Math.sin(332), 2) + Math." ascii
    $s6  = "function EkBnkZSPKReSKJvXy(HctCI){OdywdklIyHz= '';aglqDzsSEHN=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s7  = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s8  = "function zEpQGwjbNNOE(QQVnFQUYbfFlz) {return isFinite(QQVnFQUYbfFlz);}" fullword ascii
    $s9  = "function M(iXlfZHLIVfmjAx,ltCOTCpuWYZoq,NNxsNZJHvJK) {iXlfZHLIVfmjAx[ltCOTCpuWYZoq]=NNxsNZJHvJK;}" fullword ascii
    $s10 = "function VIcZChzPxGkDXCHbkSNsPMdyGpxePiqANeoyoSruvLosWFNeKQhTMR(ZrPzyVZIoKfav,TPwQuqxlEMThZX){ return SAaGrnI[NhFRmZEv[rhkYD(ZrP" ascii
    $s11 = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s12 = "function rhkYD(WKwIluZXWyq,oqDgeugMSnBMR,NfoDMwKv){arMx=SVUZYvsHIkymeioHq(WKwIluZXWyq,oqDgeugMSnBMR);BYUfC=arMx.toString(NfoDMwK" ascii
    $s13 = "v);return BYUfC;}" fullword ascii
    $s14 = "function QmuMdcuOJQBbHvq(DxXnKQVmJwwVcJRwejO) {return parseFloat(DxXnKQVmJwwVcJRwejO);}" fullword ascii
    $s15 = "function x(nZzcHGStXlWi,kepdKZsDuSpTde){nZzcHGStXlWi.push(kepdKZsDuSpTde);}" fullword ascii
    $s16 = "function VIcZChzPxGkDXCHbkSNsPMdyGpxePiqANeoyoSruvLosWFNeKQhTMR(ZrPzyVZIoKfav,TPwQuqxlEMThZX){ return SAaGrnI[NhFRmZEv[rhkYD(ZrP" ascii
    $s17 = "function SVUZYvsHIkymeioHq(kBiQIZKzGZ,NVgdPPsNuS) {return parseInt(kBiQIZKzGZ,NVgdPPsNuS);}" fullword ascii
    $s18 = "function rhkYD(WKwIluZXWyq,oqDgeugMSnBMR,NfoDMwKv){arMx=SVUZYvsHIkymeioHq(WKwIluZXWyq,oqDgeugMSnBMR);BYUfC=arMx.toString(NfoDMwK" ascii
    $s19 = "function OBNUlVR(qqCkpFiRqVQXQOnsRvsCfoXYbxIYHqmRVVZy) {return !XGiJFHsOQCA(QmuMdcuOJQBbHvq(qqCkpFiRqVQXQOnsRvsCfoXYbxIYHqmRVVZy" ascii
    $s20 = "function zZWqVzirOwDBJQB(LlkGFquJweJgnafOl,DPlpMVjnyFlJRAseDPcEACoTdvpuGfTyYS,nHySucaxeFyvyOycjhctYmcrRMAfcbAcLpZ){eval(LlkGFquJ" ascii

  condition:
    uint16(0) == 0x684e and
    8 of them
}