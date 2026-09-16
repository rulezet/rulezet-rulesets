rule sig_20151217_35debaab25a443059fd4d42ce0ecaa38 {
  meta:
    description = "datamaliciousorder - file 20151217_35debaab25a443059fd4d42ce0ecaa38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "033207ac91ad62dab3e832abf51d95c08f45cf2ba4a7d5e394a69d4338719549"

  strings:
    $s1  = "h.pow(Math.cos(865), 2) - 1)); while(true) { if(MdNyCPrVF[tUhFDOsHGSJ] > NpPtG[tUhFDOsHGSJ].length-(58+695)/753) { break; } if (" ascii
    $s2  = "w(Math.cos(585), 2) - 1)));} MdNyCPrVF[tUhFDOsHGSJ]++;}tUhFDOsHGSJ++;} return ahuqruGhzaR}" fullword ascii
    $s3  = "function UrIKbAgHpeARXwdSI(NpPtG){ahuqruGhzaR= '';tUhFDOsHGSJ=Math.round((Math.pow(Math.sin(266), 2) + Math.pow(Math.cos(266), 2" ascii
    $s4  = ") - 1));while(true){if (tUhFDOsHGSJ >= (3547+65)/602){break;}MdNyCPrVF[tUhFDOsHGSJ]=Math.round((Math.pow(Math.sin(865), 2) + Mat" ascii
    $s5  = "function UrIKbAgHpeARXwdSI(NpPtG){ahuqruGhzaR= '';tUhFDOsHGSJ=Math.round((Math.pow(Math.sin(266), 2) + Math.pow(Math.cos(266), 2" ascii
    $s6  = "function M(rIRcGuANwYKu,jvokDKAxREBYSH){rIRcGuANwYKu.push(jvokDKAxREBYSH);}" fullword ascii
    $s7  = "function UCcTBmA(yAJprAYdbBDyAFMghwtXQDvKOlRpxSgnvXjw) {return !lcPKQaQLvLL(CzZgtZhTbLyEWAd(yAJprAYdbBDyAFMghwtXQDvKOlRpxSgnvXjw" ascii
    $s8  = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s9  = "function MRQGJ(pFlvLPuFFNd,HLIYmTgACdLYq,dBpBHBWN){ueJY=eNDkDBjnHfyfiyMbw(pFlvLPuFFNd,HLIYmTgACdLYq);ohaPW=ueJY.toString(dBpBHBW" ascii
    $s10 = "N);return ohaPW;}" fullword ascii
    $s11 = "function lJMXSHOKltPaUdyQawMxhswfSHJklVxQEIPjrUHkLcCePDwGZoeLFs(qLXlAHHgaqbwt,QwwIYqsqstBaup){ return OCSIFEZ[KqwqZELl[MRQGJ(qLX" ascii
    $s12 = "function XpfGYRqOVOIcpVN(fIyoOCYgPqMZUafSV,CTbBnUnVumetzWNMvyEGCqqVbzmUsMbmne,UAFokJQiSjLbBFbzeetFnGaWiZXbqMamjpi){eval(fIyoOCYg" ascii
    $s13 = "function UCcTBmA(yAJprAYdbBDyAFMghwtXQDvKOlRpxSgnvXjw) {return !lcPKQaQLvLL(CzZgtZhTbLyEWAd(yAJprAYdbBDyAFMghwtXQDvKOlRpxSgnvXjw" ascii
    $s14 = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s15 = "function CzZgtZhTbLyEWAd(stGaJuhTymSIInkqCIZ) {return parseFloat(stGaJuhTymSIInkqCIZ);}" fullword ascii
    $s16 = "function MRQGJ(pFlvLPuFFNd,HLIYmTgACdLYq,dBpBHBWN){ueJY=eNDkDBjnHfyfiyMbw(pFlvLPuFFNd,HLIYmTgACdLYq);ohaPW=ueJY.toString(dBpBHBW" ascii
    $s17 = "function y(CFNKRjKneEOMMw,imzAQvTUcivjT,YRgwDZVDHQw) {CFNKRjKneEOMMw[imzAQvTUcivjT]=YRgwDZVDHQw;}" fullword ascii
    $s18 = "function lJMXSHOKltPaUdyQawMxhswfSHJklVxQEIPjrUHkLcCePDwGZoeLFs(qLXlAHHgaqbwt,QwwIYqsqstBaup){ return OCSIFEZ[KqwqZELl[MRQGJ(qLX" ascii
    $s19 = "function TyfJAVsNTHZY(JaKDOEGmVXaKV) {return isFinite(JaKDOEGmVXaKV);}" fullword ascii
    $s20 = "function XpfGYRqOVOIcpVN(fIyoOCYgPqMZUafSV,CTbBnUnVumetzWNMvyEGCqqVbzmUsMbmne,UAFokJQiSjLbBFbzeetFnGaWiZXbqMamjpi){eval(fIyoOCYg" ascii

  condition:
    uint16(0) == 0x714b and
    8 of them
}