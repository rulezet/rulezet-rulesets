rule sig_20151217_1023dff41ef4443e77d3c844ae4c6640 {
  meta:
    description = "datamaliciousorder - file 20151217_1023dff41ef4443e77d3c844ae4c6640.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37073e5a342233340132e9cfd6824a70d9a77afe7745070183331b48f4f46c37"

  strings:
    $s1  = "ow(Math.cos(470), 2) - 1)));} WoZObeFBL[pmJHthEExEh]++;}pmJHthEExEh++;} return LOeGzJfEGNt}" fullword ascii
    $s2  = ") - 1));while(true){if (pmJHthEExEh >= (-653+809)/26){break;}WoZObeFBL[pmJHthEExEh]=Math.round((Math.pow(Math.sin(433), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(433), 2) - 1)); while(true) { if(WoZObeFBL[pmJHthEExEh] > jKCIf[pmJHthEExEh].length-(-520+776)/256) { break; } if" ascii
    $s4  = "function gZQJGivgPqhpbwilP(jKCIf){LOeGzJfEGNt= '';pmJHthEExEh=Math.round((Math.pow(Math.sin(862), 2) + Math.pow(Math.cos(862), 2" ascii
    $s5  = "function gZQJGivgPqhpbwilP(jKCIf){LOeGzJfEGNt= '';pmJHthEExEh=Math.round((Math.pow(Math.sin(862), 2) + Math.pow(Math.cos(862), 2" ascii
    $s6  = "function cUSwNNP(EjYQizkZrvKEiBbJPBPREeGPcnkyFPjhaCWd) {return !TmDgwzaEbqZ(mKjagiOVXaaqKEf(EjYQizkZrvKEiBbJPBPREeGPcnkyFPjhaCWd" ascii
    $s7  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s8  = "function siCCOlbdXFHcsNC(COkXsLQwUlyOozJvk,RYICHcQTXatdjSQJvBECzsVMTWODnhhHGr,kLDZKvUoxuyZkQpouDzAYXQdnNfrPHYoBkv){eval(COkXsLQw" ascii
    $s9  = "function JKLqHDpGfGYZ(mHlEoMwqhdlQi) {return isFinite(mHlEoMwqhdlQi);}" fullword ascii
    $s10 = "function cUSwNNP(EjYQizkZrvKEiBbJPBPREeGPcnkyFPjhaCWd) {return !TmDgwzaEbqZ(mKjagiOVXaaqKEf(EjYQizkZrvKEiBbJPBPREeGPcnkyFPjhaCWd" ascii
    $s11 = "v);return BYdQp;}" fullword ascii
    $s12 = "function beNld(lIIXbLvebde,CjvGvvQrUxcxg,zGBKzGLv){KIcs=tPPMRYzcgvdvkjuks(lIIXbLvebde,CjvGvvQrUxcxg);BYdQp=KIcs.toString(zGBKzGL" ascii
    $s13 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s14 = "function tPPMRYzcgvdvkjuks(oSVpTNJlId,WcLHaOqJeX) {return parseInt(oSVpTNJlId,WcLHaOqJeX);}" fullword ascii
    $s15 = "function TmDgwzaEbqZ(ClTGrNVjkorHQT) {return isNaN(ClTGrNVjkorHQT);}" fullword ascii
    $s16 = "function mKjagiOVXaaqKEf(pUhaJXwYbfgifTVmuWG) {return parseFloat(pUhaJXwYbfgifTVmuWG);}" fullword ascii
    $s17 = "function siCCOlbdXFHcsNC(COkXsLQwUlyOozJvk,RYICHcQTXatdjSQJvBECzsVMTWODnhhHGr,kLDZKvUoxuyZkQpouDzAYXQdnNfrPHYoBkv){eval(COkXsLQw" ascii
    $s18 = "function beNld(lIIXbLvebde,CjvGvvQrUxcxg,zGBKzGLv){KIcs=tPPMRYzcgvdvkjuks(lIIXbLvebde,CjvGvvQrUxcxg);BYdQp=KIcs.toString(zGBKzGL" ascii
    $s19 = "function NiWlAhsEgpklhnLzheFBRltkiHgpxUmPcDuxPLNaaChzwRzPXTOcOF(jFMgEwZdeyRHI,kqRzDjMpQAzCTj){ return KxarNCM[MAMgDiMp[beNld(jFM" ascii
    $s20 = "function f(CCwnFRdvnvrh,pvqPPgTwmshhRN){CCwnFRdvnvrh.push(pvqPPgTwmshhRN);}" fullword ascii

  condition:
    uint16(0) == 0x414d and
    8 of them
}