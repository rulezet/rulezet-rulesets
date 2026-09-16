rule sig_20151217_901b4ea15a91ceb3d98cc7c71016ea5a {
  meta:
    description = "datamaliciousorder - file 20151217_901b4ea15a91ceb3d98cc7c71016ea5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf1e9a99190cef17b0e187e515077dd0e29cbd0d5ee29bd7374eebfff7d9df30"

  strings:
    $s1  = "function QUDtokeCLTMCVUHps(yGTrW){qRREJAHDaYX= '';zRnbsLvhrcQ=Math.round((Math.pow(Math.sin(338), 2) + Math.pow(Math.cos(338), 2" ascii
    $s2  = ") - 1));while(true){if (zRnbsLvhrcQ >= (863+799)/277){break;}sSJxcbamL[zRnbsLvhrcQ]=Math.round((Math.pow(Math.sin(686), 2) + Mat" ascii
    $s3  = "ow(Math.cos(206), 2) - 1)));} sSJxcbamL[zRnbsLvhrcQ]++;}zRnbsLvhrcQ++;} return qRREJAHDaYX}" fullword ascii
    $s4  = "h.pow(Math.cos(686), 2) - 1)); while(true) { if(sSJxcbamL[zRnbsLvhrcQ] > yGTrW[zRnbsLvhrcQ].length-(337+334)/671) { break; } if " ascii
    $s5  = "function QUDtokeCLTMCVUHps(yGTrW){qRREJAHDaYX= '';zRnbsLvhrcQ=Math.round((Math.pow(Math.sin(338), 2) + Math.pow(Math.cos(338), 2" ascii
    $s6  = "function xmjCidm(rXfLJlYzniPcWFRtWASfxEpVukdrYLsWVPJh) {return !RzgISPbKhGj(oWWcsVrewgKAgke(rXfLJlYzniPcWFRtWASfxEpVukdrYLsWVPJh" ascii
    $s7  = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s8  = ",'V','J','?','S','7','0','C','W',']','p','!','-','X','.','_','Y','0','[',']','t','h','Z','^','l','`','0','D','[','d','Y',String." ascii
    $s9  = "function xmjCidm(rXfLJlYzniPcWFRtWASfxEpVukdrYLsWVPJh) {return !RzgISPbKhGj(oWWcsVrewgKAgke(rXfLJlYzniPcWFRtWASfxEpVukdrYLsWVPJh" ascii
    $s10 = "q);return zddjF;}" fullword ascii
    $s11 = "function oWWcsVrewgKAgke(SJDNvupcGdqMNnmiJxd) {return parseFloat(SJDNvupcGdqMNnmiJxd);}" fullword ascii
    $s12 = "function QLQkCMmbeYPSxyPprbpRxmIVTmKNBIrXNUElVMaYUoMmrlsyQRRzbw(bQyyZsrSGjwHl,gJhivYDvPBgDao){ return iQstGod[wbiMbDPT[LqVty(bQy" ascii
    $s13 = "function RzgISPbKhGj(wfVrhjuzyNGxIp) {return isNaN(wfVrhjuzyNGxIp);}" fullword ascii
    $s14 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s15 = "function Y(FDDghQBkLggA,swJUztEWRoxWZS){FDDghQBkLggA.push(swJUztEWRoxWZS);}" fullword ascii
    $s16 = "function QLQkCMmbeYPSxyPprbpRxmIVTmKNBIrXNUElVMaYUoMmrlsyQRRzbw(bQyyZsrSGjwHl,gJhivYDvPBgDao){ return iQstGod[wbiMbDPT[LqVty(bQy" ascii
    $s17 = "function LqVty(qykNAlDivAK,CncoDTkbyiBOd,LCOowykq){aQdS=MshGiKahjXqTpwnHK(qykNAlDivAK,CncoDTkbyiBOd);zddjF=aQdS.toString(LCOowyk" ascii
    $s18 = "function y(tpdVpzsBLwNDEs,rUsOsmDvDxmVO,LULygGwsJxO) {tpdVpzsBLwNDEs[rUsOsmDvDxmVO]=LULygGwsJxO;}" fullword ascii
    $s19 = "function CNnEwvEBfHwM(MQFymTvEBgCvm) {return isFinite(MQFymTvEBgCvm);}" fullword ascii
    $s20 = "function MzrcjEEpdQZTlRu(UVUBCsmBuXXrbOXgi,EaSrieTICmJDZUtCwFLmuVhTHnIhDXDpZZ,mQaYnbGexYxLEfpczAwpLdCcEykZvQDisve){eval(UVUBCsmB" ascii

  condition:
    uint16(0) == 0x6277 and
    8 of them
}