rule sig_20151216_6f84cac9d9b8bef08a0483af663feef4 {
  meta:
    description = "datamaliciousorder - file 20151216_6f84cac9d9b8bef08a0483af663feef4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14a2bb9a9311ae33f864147af7b2cb2acb6277a683b76e49782ec2d4404e68eb"

  strings:
    $s1  = "h.pow(Math.cos(81), 2) - 1)); while(true) { if(jlBdBMZfJ[ibuoMRpUHei] > AcUul[ibuoMRpUHei].length-(-200+299)/99) { break; } if (" ascii
    $s2  = "w(Math.cos(146), 2) - 1)));} jlBdBMZfJ[ibuoMRpUHei]++;}ibuoMRpUHei++;} return OTkzneWXHwx}" fullword ascii
    $s3  = ") - 1));while(true){if (ibuoMRpUHei >= (4969+365)/889){break;}jlBdBMZfJ[ibuoMRpUHei]=Math.round((Math.pow(Math.sin(81), 2) + Mat" ascii
    $s4  = "function XPefBCoitBDsijJfo(AcUul){OTkzneWXHwx= '';ibuoMRpUHei=Math.round((Math.pow(Math.sin(594), 2) + Math.pow(Math.cos(594), 2" ascii
    $s5  = "function XPefBCoitBDsijJfo(AcUul){OTkzneWXHwx= '';ibuoMRpUHei=Math.round((Math.pow(Math.sin(594), 2) + Math.pow(Math.cos(594), 2" ascii
    $s6  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s7  = ",'(',')','9','C','6','P','D','`','W','v','v','<','X','[','w',' ','d','U','Y','?','Z','a','F','I','[',']','B','$','N','L',String." ascii
    $s8  = "function sGwUUFBfAaNZUomXb(lInAWERCWc,PuzwyoygID) {return parseInt(lInAWERCWc,PuzwyoygID);}" fullword ascii
    $s9  = "function F(rXfWmHZUwSJlMP,sBsGDxWlaygWp,NcWMXxBmDqG) {rXfWmHZUwSJlMP[sBsGDxWlaygWp]=NcWMXxBmDqG;}" fullword ascii
    $s10 = "function NvQHoWAQUAQ(GAXeKuBFkHLVgF) {return isNaN(GAXeKuBFkHLVgF);}" fullword ascii
    $s11 = "function lTTXToOhuaBHZnV(KvAEckbOGnjehWoCepQ) {return parseFloat(KvAEckbOGnjehWoCepQ);}" fullword ascii
    $s12 = "function ynpsglznxloR(aJzqCUKoksFlJ) {return isFinite(aJzqCUKoksFlJ);}" fullword ascii
    $s13 = "Z);return hldkQ;}" fullword ascii
    $s14 = "function rRhacHucdtcWwrm(QzkSApZnaObmVPqzk,QixNaCEfEoFBFXstOXeuViAGwMjwSJDqYY,AXVbhKqcQQXvfeCPkkvbzSMwqqziQWuxaWv){eval(QzkSApZn" ascii
    $s15 = "function T(PZXtqFDxrEBX,DXRHBPRMwIWOil){PZXtqFDxrEBX.push(DXRHBPRMwIWOil);}" fullword ascii
    $s16 = "function NkJpV(PvHVyMgcgdC,EGbADByZcSjQb,OuFHWwbZ){Nhgx=sGwUUFBfAaNZUomXb(PvHVyMgcgdC,EGbADByZcSjQb);hldkQ=Nhgx.toString(OuFHWwb" ascii
    $s17 = "function rRhacHucdtcWwrm(QzkSApZnaObmVPqzk,QixNaCEfEoFBFXstOXeuViAGwMjwSJDqYY,AXVbhKqcQQXvfeCPkkvbzSMwqqziQWuxaWv){eval(QzkSApZn" ascii
    $s18 = "function NkJpV(PvHVyMgcgdC,EGbADByZcSjQb,OuFHWwbZ){Nhgx=sGwUUFBfAaNZUomXb(PvHVyMgcgdC,EGbADByZcSjQb);hldkQ=Nhgx.toString(OuFHWwb" ascii
    $s19 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s20 = "function opNrtJE(AEsbccaIMhqGRYcGhcjKfmGzBNZpaamGuAZd) {return !NvQHoWAQUAQ(lTTXToOhuaBHZnV(AEsbccaIMhqGRYcGhcjKfmGzBNZpaamGuAZd" ascii

  condition:
    uint16(0) == 0x6b77 and
    8 of them
}