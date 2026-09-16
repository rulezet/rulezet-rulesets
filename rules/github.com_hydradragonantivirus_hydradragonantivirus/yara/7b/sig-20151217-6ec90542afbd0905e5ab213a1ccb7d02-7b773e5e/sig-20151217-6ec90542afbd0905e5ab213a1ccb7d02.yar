rule sig_20151217_6ec90542afbd0905e5ab213a1ccb7d02 {
  meta:
    description = "datamaliciousorder - file 20151217_6ec90542afbd0905e5ab213a1ccb7d02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffe3dc1fc89379ae7cd7356628325f7e8744c3f2f72f1e69e01ceef6c617f839"

  strings:
    $s1  = "function ratqUqhklYMfCdRYh(LBWzD){ffCcnfPSGBk= '';atyAZGQsBkk=Math.round((Math.pow(Math.sin(247), 2) + Math.pow(Math.cos(247), 2" ascii
    $s2  = ") - 1));while(true){if (atyAZGQsBkk >= (-35+887)/142){break;}eMafKeAhR[atyAZGQsBkk]=Math.round((Math.pow(Math.sin(739), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(739), 2) - 1)); while(true) { if(eMafKeAhR[atyAZGQsBkk] > LBWzD[atyAZGQsBkk].length-(-718+790)/72) { break; } if " ascii
    $s4  = "ow(Math.cos(435), 2) - 1)));} eMafKeAhR[atyAZGQsBkk]++;}atyAZGQsBkk++;} return ffCcnfPSGBk}" fullword ascii
    $s5  = "function ratqUqhklYMfCdRYh(LBWzD){ffCcnfPSGBk= '';atyAZGQsBkk=Math.round((Math.pow(Math.sin(247), 2) + Math.pow(Math.cos(247), 2" ascii
    $s6  = "function pIBVAdV(lspNHIbEtpYtrhuKBuBqbIMvPJLxoQNgHfVj) {return !uCUOUvaGvUl(TsMtVWhlfyGpgdV(lspNHIbEtpYtrhuKBuBqbIMvPJLxoQNgHfVj" ascii
    $s7  = "function m(SvBhAShZeazV,iYoaohzYOrVkkd){SvBhAShZeazV.push(iYoaohzYOrVkkd);}" fullword ascii
    $s8  = "function uCUOUvaGvUl(OTFSlkmwTvVlcz) {return isNaN(OTFSlkmwTvVlcz);}" fullword ascii
    $s9  = "function pIBVAdV(lspNHIbEtpYtrhuKBuBqbIMvPJLxoQNgHfVj) {return !uCUOUvaGvUl(TsMtVWhlfyGpgdV(lspNHIbEtpYtrhuKBuBqbIMvPJLxoQNgHfVj" ascii
    $s10 = "function loTQB(PCPkZVvLBaM,PtodGyTDFeUzi,TLngdQAg){WBKo=AdtJEsfEZJSMJRtKZ(PCPkZVvLBaM,PtodGyTDFeUzi);SoSIR=WBKo.toString(TLngdQA" ascii
    $s11 = "function qqsLuuathYmOBzs(cXjyQvrAIZOhgUshI,lmQjQiCXJbgmIhJElavmqvBTveplhvLkDe,bUSVhWSnpHpmwtsfKwLtsETZTcWbPnUBpwN){eval(cXjyQvrA" ascii
    $s12 = "function loTQB(PCPkZVvLBaM,PtodGyTDFeUzi,TLngdQAg){WBKo=AdtJEsfEZJSMJRtKZ(PCPkZVvLBaM,PtodGyTDFeUzi);SoSIR=WBKo.toString(TLngdQA" ascii
    $s13 = "function qScIJcCrVurDrPjvYGHtnrNmXWQncICFlSiOpkxEczKnJLVDzsKHpR(SEEvQqixZBHaw,zyAvXDPLegGfAF){ return rXFLYLg[FzaaaPxR[loTQB(SEE" ascii
    $s14 = "function AdtJEsfEZJSMJRtKZ(ghlVMRbGLb,bttwWTutea) {return parseInt(ghlVMRbGLb,bttwWTutea);}" fullword ascii
    $s15 = "function TsMtVWhlfyGpgdV(DJkNSBFQjXmHKvtDIoy) {return parseFloat(DJkNSBFQjXmHKvtDIoy);}" fullword ascii
    $s16 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s17 = "function ChvENZMQWzvp(ZoPdcujupJIiy) {return isFinite(ZoPdcujupJIiy);}" fullword ascii
    $s18 = "function a(WorTAFvcTPNtAb,NWWixHtsWtJsR,xHzKmtrfeVg) {WorTAFvcTPNtAb[NWWixHtsWtJsR]=xHzKmtrfeVg;}" fullword ascii
    $s19 = "function qqsLuuathYmOBzs(cXjyQvrAIZOhgUshI,lmQjQiCXJbgmIhJElavmqvBTveplhvLkDe,bUSVhWSnpHpmwtsfKwLtsETZTcWbPnUBpwN){eval(cXjyQvrA" ascii
    $s20 = "function qScIJcCrVurDrPjvYGHtnrNmXWQncICFlSiOpkxEczKnJLVDzsKHpR(SEEvQqixZBHaw,zyAvXDPLegGfAF){ return rXFLYLg[FzaaaPxR[loTQB(SEE" ascii

  condition:
    uint16(0) == 0x7a46 and
    8 of them
}