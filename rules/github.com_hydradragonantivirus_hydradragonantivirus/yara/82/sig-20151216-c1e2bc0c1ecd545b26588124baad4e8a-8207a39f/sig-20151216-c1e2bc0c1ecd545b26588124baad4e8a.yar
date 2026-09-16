rule sig_20151216_c1e2bc0c1ecd545b26588124baad4e8a {
  meta:
    description = "datamaliciousorder - file 20151216_c1e2bc0c1ecd545b26588124baad4e8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27d5644c475dbfa7a8f40c45c53130ab686a9b665c056e37b2f2650e5f6baa4a"

  strings:
    $s1  = "w(Math.cos(910), 2) - 1)));} hcMQpAmyJ[TKaxLaDPZBC]++;}TKaxLaDPZBC++;} return GtIEplhcHqx}" fullword ascii
    $s2  = "function cZFyTMijgauyeblbY(owTtB){GtIEplhcHqx= '';TKaxLaDPZBC=Math.round((Math.pow(Math.sin(834), 2) + Math.pow(Math.cos(834), 2" ascii
    $s3  = "h.pow(Math.cos(740), 2) - 1)); while(true) { if(hcMQpAmyJ[TKaxLaDPZBC] > owTtB[TKaxLaDPZBC].length-(-615+781)/166) { break; } if" ascii
    $s4  = ") - 1));while(true){if (TKaxLaDPZBC >= (-84+726)/107){break;}hcMQpAmyJ[TKaxLaDPZBC]=Math.round((Math.pow(Math.sin(740), 2) + Mat" ascii
    $s5  = "function cZFyTMijgauyeblbY(owTtB){GtIEplhcHqx= '';TKaxLaDPZBC=Math.round((Math.pow(Math.sin(834), 2) + Math.pow(Math.cos(834), 2" ascii
    $s6  = "function hKdJCFE(IqdKFJoNavtOhwwzRYqgwsHFENfbbkwLUhqt) {return !qtNHZLWKPpb(kuyKSkXPrRLUcUs(IqdKFJoNavtOhwwzRYqgwsHFENfbbkwLUhqt" ascii
    $s7  = "function LJUAn(JbExKXrqIeF,mmTeZRWXckoSE,BLsUwLKt){cfCC=FdXlFdLbrRobUBfFh(JbExKXrqIeF,mmTeZRWXckoSE);OIdSi=cfCC.toString(BLsUwLK" ascii
    $s8  = "function kuyKSkXPrRLUcUs(hUHOIHXvFOlpQEvLPIE) {return parseFloat(hUHOIHXvFOlpQEvLPIE);}" fullword ascii
    $s9  = "function hKdJCFE(IqdKFJoNavtOhwwzRYqgwsHFENfbbkwLUhqt) {return !qtNHZLWKPpb(kuyKSkXPrRLUcUs(IqdKFJoNavtOhwwzRYqgwsHFENfbbkwLUhqt" ascii
    $s10 = "function qtNHZLWKPpb(TTyUgBieOcknjJ) {return isNaN(TTyUgBieOcknjJ);}" fullword ascii
    $s11 = "function iPeNBIxIrqGz(enrlJWklakmzH) {return isFinite(enrlJWklakmzH);}" fullword ascii
    $s12 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s13 = "function njDeeQadscioybwqSkxAWaqWniZUhPrVJbWFfxuCkmohGOJSXUKwvH(NUHNAwRyZvpEh,cGzZmsEhAAOylg){ return OLkubNU[VjRqpWvn[LJUAn(NUH" ascii
    $s14 = "function R(NLuSyVOxWIeX,hxrKYbwcwJeBGi){NLuSyVOxWIeX.push(hxrKYbwcwJeBGi);}" fullword ascii
    $s15 = "function Y(rHeOFlNXLYZkOO,ORevIZsAkvEqw,VomqKmwPlAs) {rHeOFlNXLYZkOO[ORevIZsAkvEqw]=VomqKmwPlAs;}" fullword ascii
    $s16 = "function FdXlFdLbrRobUBfFh(SSlFYueryj,zkLGfyQAeJ) {return parseInt(SSlFYueryj,zkLGfyQAeJ);}" fullword ascii
    $s17 = "function sRNoVffwwRfHbfW(joijzWEaVgdVXrpif,csDcoJAfCFlEIytHRguDmnsbCwwOCBJNnN,HMeZaqeXGVapyGOFATElOzysZVKHoILEyrV){eval(joijzWEa" ascii
    $s18 = "function LJUAn(JbExKXrqIeF,mmTeZRWXckoSE,BLsUwLKt){cfCC=FdXlFdLbrRobUBfFh(JbExKXrqIeF,mmTeZRWXckoSE);OIdSi=cfCC.toString(BLsUwLK" ascii
    $s19 = "function sRNoVffwwRfHbfW(joijzWEaVgdVXrpif,csDcoJAfCFlEIytHRguDmnsbCwwOCBJNnN,HMeZaqeXGVapyGOFATElOzysZVKHoILEyrV){eval(joijzWEa" ascii
    $s20 = "t);return OIdSi;}" fullword ascii

  condition:
    uint16(0) == 0x6a56 and
    8 of them
}