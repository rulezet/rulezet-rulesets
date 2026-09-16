rule sig_20151217_0ebd180baf0d995baf701f6418e0fa99 {
  meta:
    description = "datamaliciousorder - file 20151217_0ebd180baf0d995baf701f6418e0fa99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf325215d58d3f478a3f2c68bcd8b8a8edb83bf1a0f2058d0c0f702832c6cdc4"

  strings:
    $s1  = "(Math.cos(616), 2) - 1)));} PCKcDWYGh[ybvRanYFFiz]++;}ybvRanYFFiz++;} return cUGNGBaIFKT}" fullword ascii
    $s2  = "th.pow(Math.cos(529), 2) - 1)); while(true) { if(PCKcDWYGh[ybvRanYFFiz] > RoTRa[ybvRanYFFiz].length-(58+670)/728) { break; } if " ascii
    $s3  = ") - 1));while(true){if (ybvRanYFFiz >= (1290+864)/359){break;}PCKcDWYGh[ybvRanYFFiz]=Math.round((Math.pow(Math.sin(529), 2) + Ma" ascii
    $s4  = "function VniOLwpHLpvROsSoR(RoTRa){cUGNGBaIFKT= '';ybvRanYFFiz=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s5  = "function VniOLwpHLpvROsSoR(RoTRa){cUGNGBaIFKT= '';ybvRanYFFiz=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s6  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s7  = "function U(TsyettuLLWhPnN,KKCUlXaJfOBkb,UrwaNeKXguC) {TsyettuLLWhPnN[KKCUlXaJfOBkb]=UrwaNeKXguC;}" fullword ascii
    $s8  = "function dUKHk(bKsnRjsEOhT,WhKFWdlqbNghe,FvDKvHVN){eRaL=aarbEQKyETkQkLJnV(bKsnRjsEOhT,WhKFWdlqbNghe);EtWkm=eRaL.toString(FvDKvHV" ascii
    $s9  = "N);return EtWkm;}" fullword ascii
    $s10 = ",'V','^','&','+','1','W','V','+','$','X','N','X','T','M','P','j','Y','B','=','O',')','r','Z','@',')','8','[','(','b','B',String." ascii
    $s11 = "function bqXtfShVpuVFtmW(axCMWTMtjlqsAEXXi,ASLvCPZuiyucfvKFtdiJtcntQsoFUoZnHy,KpZqXsZjOVNKoUHtGLwDOtofsfTecDlnJAb){eval(axCMWTMt" ascii
    $s12 = "function dUKHk(bKsnRjsEOhT,WhKFWdlqbNghe,FvDKvHVN){eRaL=aarbEQKyETkQkLJnV(bKsnRjsEOhT,WhKFWdlqbNghe);EtWkm=eRaL.toString(FvDKvHV" ascii
    $s13 = "function kfMxTOltwVYekElWRcFReeZynMrrAgZtATMNSEIPtlpBgaCPUXviXS(dUbkOAKdCwBfj,aGOQrWlhzPrmcL){ return KcWZvrj[WaIKRrct[dUKHk(dUb" ascii
    $s14 = "function LHaFSRmcZaLE(zClgpzChbtUGT) {return isFinite(zClgpzChbtUGT);}" fullword ascii
    $s15 = "function aarbEQKyETkQkLJnV(iOmZuduqSF,YeNgIbBvTh) {return parseInt(iOmZuduqSF,YeNgIbBvTh);}" fullword ascii
    $s16 = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s17 = "function ucXyEJjUKRBxNJQ(dSEDUetpxEEioPsDxLG) {return parseFloat(dSEDUetpxEEioPsDxLG);}" fullword ascii
    $s18 = "function kfMxTOltwVYekElWRcFReeZynMrrAgZtATMNSEIPtlpBgaCPUXviXS(dUbkOAKdCwBfj,aGOQrWlhzPrmcL){ return KcWZvrj[WaIKRrct[dUKHk(dUb" ascii
    $s19 = "function E(BEWJOvDMnazP,RhnwYEJNtsnKVQ){BEWJOvDMnazP.push(RhnwYEJNtsnKVQ);}" fullword ascii
    $s20 = "function bqXtfShVpuVFtmW(axCMWTMtjlqsAEXXi,ASLvCPZuiyucfvKFtdiJtcntQsoFUoZnHy,KpZqXsZjOVNKoUHtGLwDOtofsfTecDlnJAb){eval(axCMWTMt" ascii

  condition:
    uint16(0) == 0x6157 and
    8 of them
}