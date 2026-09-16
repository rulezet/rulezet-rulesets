rule sig_20151215_d0d1309c1791ee503c68bed0a2a7ce6b {
  meta:
    description = "datamaliciousorder - file 20151215_d0d1309c1791ee503c68bed0a2a7ce6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dd29bcbe04b75db4cf8133f730b19cb66bd8d0d009f4d342d09af7e40c3895b"

  strings:
    $s1  = "ath.pow(Math.cos(584), 2) - 1)); while(true) { if(wmVBWviCK[tDaEZYPUFEQ] > fXjLr[tDaEZYPUFEQ].length-(73+453)/526) { break; } if" ascii
    $s2  = "pow(Math.cos(175), 2) - 1)));} wmVBWviCK[tDaEZYPUFEQ]++;}} return ucZDEkzFHZu}" fullword ascii
    $s3  = "function fHfSOoJrJjLYXozkQ(fXjLr){ucZDEkzFHZu= Z[1767];for(tDaEZYPUFEQ=Math.round((Math.pow(Math.sin(368), 2) + Math.pow(Math.co" ascii
    $s4  = "function fHfSOoJrJjLYXozkQ(fXjLr){ucZDEkzFHZu= Z[1767];for(tDaEZYPUFEQ=Math.round((Math.pow(Math.sin(368), 2) + Math.pow(Math.co" ascii
    $s5  = "uxjLHWXayUzFfFwJpRlGCXRmpahyGQcmnXL([fXjLr[tDaEZYPUFEQ][wmVBWviCK[tDaEZYPUFEQ]]], Math.round((Math.pow(Math.sin(175), 2) + Math." ascii
    $s6  = "function ptrik(RxYkSWMPKvk,OssLfkHHpkBPb,oqhXaDbn){syvZ=parseInt(RxYkSWMPKvk,OssLfkHHpkBPb);ZDUKp=syvZ.toString(oqhXaDbn);return" ascii
    $s7  = " ZDUKp;}function EWhauNQUsMcWsqP(APmfpZqjUtBfrUeyE,fqOYzTmXfQiUjUVEGjmemWUjoYLSIZKtrJ,JxFZJFaSsMwWAjUlVRuLPkqVuRwWAOCvSTn){eval(" ascii
    $s8  = "function TyvzxgtqaAG(XwjjkaLM,WxIRCx){return XwjjkaLM.split(WxIRCx)}" fullword ascii
    $s9  = "function EWhauNQUsMcWsqP(APmfpZqjUtBfrUeyE){eval(APmfpZqjUtBfrUeyE)}" fullword ascii
    $s10 = "cMaN)) {return (String.fromCharCode(DIJfDPsbGQyqcMaN) + String.fromCharCode((75319+45)/908));}}" fullword ascii
    $s11 = "function X(TYKjcWIxxOXs,ohrrzLXSgyBhqd){TYKjcWIxxOXs.push(ohrrzLXSgyBhqd);}function G2(DIJfDPsbGQyqcMaN){if(HSAGlFs(DIJfDPsbGQyq" ascii
    $s12 = "var Z=new Array();" fullword ascii
    $s13 = "function mIwUymDYNawVozAZIDSuxjLHWXayUzFfFwJpRlGCXRmpahyGQcmnXL(LjhbGXMVnbMdw,UpGnAeJfEkywmB){ return VftyITE[fEeurlVY[ptrik(Ljh" ascii
    $s14 = "function mIwUymDYNawVozAZIDSuxjLHWXayUzFfFwJpRlGCXRmpahyGQcmnXL(LjhbGXMVnbMdw,UpGnAeJfEkywmB){ return VftyITE[fEeurlVY[ptrik(Ljh" ascii
    $s15 = "function ptrik(RxYkSWMPKvk,OssLfkHHpkBPb,oqhXaDbn){syvZ=parseInt(RxYkSWMPKvk,OssLfkHHpkBPb);ZDUKp=syvZ.toString(oqhXaDbn);return" ascii
    $s16 = "function X(TYKjcWIxxOXs,ohrrzLXSgyBhqd){TYKjcWIxxOXs.push(ohrrzLXSgyBhqd);}function G2(DIJfDPsbGQyqcMaN){if(HSAGlFs(DIJfDPsbGQyq" ascii
    $s17 = "function HSAGlFs(HIFMFccAiEdmtvHaOhSnKJjryGWllCMWyyZX) {return !isNaN(parseFloat(HIFMFccAiEdmtvHaOhSnKJjryGWllCMWyyZX)) && isFin" ascii
    $s18 = "function HSAGlFs(HIFMFccAiEdmtvHaOhSnKJjryGWllCMWyyZX) {return !isNaN(parseFloat(HIFMFccAiEdmtvHaOhSnKJjryGWllCMWyyZX)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}