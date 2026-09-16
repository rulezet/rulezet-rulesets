rule sig_20151214_f14e6344a87d889120a87ccb7e138f24 {
  meta:
    description = "datamaliciousorder - file 20151214_f14e6344a87d889120a87ccb7e138f24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47ab861994992485874abc013950f3412ebd8461be06b53ca6505e70912da462"

  strings:
    $s1  = "ath.pow(Math.cos(467), 2) - 1)); while(true) { if(zqSwBEeBo[ABjnGhijDoX] > Hduop[ABjnGhijDoX].length-(-574+834)/260) { break; } " ascii
    $s2  = "h.pow(Math.cos(583), 2) - 1)));} zqSwBEeBo[ABjnGhijDoX]++;}} return vWAWUKRyaAZ}" fullword ascii
    $s3  = "function hgbcHEzBWCSdCIFCG(Hduop){vWAWUKRyaAZ= L[1779];for(ABjnGhijDoX=Math.round((Math.pow(Math.sin(451), 2) + Math.pow(Math.co" ascii
    $s4  = "function hgbcHEzBWCSdCIFCG(Hduop){vWAWUKRyaAZ= L[1779];for(ABjnGhijDoX=Math.round((Math.pow(Math.sin(451), 2) + Math.pow(Math.co" ascii
    $s5  = "rGHA)) {return (String.fromCharCode(nIcnBqdlXMUhrGHA) + String.fromCharCode((36668+708)/584));}}" fullword ascii
    $s6  = "var L=new Array();" fullword ascii
    $s7  = "function G(nOfwnAaaOQsw,bXNkNWfNSycsaY){nOfwnAaaOQsw.push(bXNkNWfNSycsaY);}function j7(nIcnBqdlXMUhrGHA){if(OXDacAy(nIcnBqdlXMUh" ascii
    $s8  = "function vTpdhQtjHHvVFZZemfCmWMeAcQRllHQpgKAMJiMFyohojbYKrQHfhC(gihaOncwdCyiP,QkmJHtJTOZxymo){ return momRsUc[EnIfrLet[JGhVF(gih" ascii
    $s9  = "function vTpdhQtjHHvVFZZemfCmWMeAcQRllHQpgKAMJiMFyohojbYKrQHfhC(gihaOncwdCyiP,QkmJHtJTOZxymo){ return momRsUc[EnIfrLet[JGhVF(gih" ascii
    $s10 = "function uLfVWSQKaBuzfkm(LiYZdZoWaPQaHGque){eval(LiYZdZoWaPQaHGque)}" fullword ascii
    $s11 = "function JGhVF(whXVdQDjERj,YDlCsiymqgweR,sssRCpQx){WiVW=parseInt(whXVdQDjERj,YDlCsiymqgweR);AAaMM=WiVW.toString(sssRCpQx);return" ascii
    $s12 = "function JGhVF(whXVdQDjERj,YDlCsiymqgweR,sssRCpQx){WiVW=parseInt(whXVdQDjERj,YDlCsiymqgweR);AAaMM=WiVW.toString(sssRCpQx);return" ascii
    $s13 = " AAaMM;}function uLfVWSQKaBuzfkm(LiYZdZoWaPQaHGque,aJOoWFjwFPjrCrCxsMnkgzltcDhSpTQPzn,ZAsxNgLehKlxDLRjpXXGjwYtmGUPZXCXtRi){eval(" ascii
    $s14 = "function JLnkcjRhVEJ(hSlBFbEP,leuqpz){return hSlBFbEP.split(leuqpz)}" fullword ascii
    $s15 = "function OXDacAy(dDvWucOVYMEGtSkvkvoAVKpxqwFcIFVVYPSi) {return !isNaN(parseFloat(dDvWucOVYMEGtSkvkvoAVKpxqwFcIFVVYPSi)) && isFin" ascii
    $s16 = "function OXDacAy(dDvWucOVYMEGtSkvkvoAVKpxqwFcIFVVYPSi) {return !isNaN(parseFloat(dDvWucOVYMEGtSkvkvoAVKpxqwFcIFVVYPSi)) && isFin" ascii
    $s17 = "function G(nOfwnAaaOQsw,bXNkNWfNSycsaY){nOfwnAaaOQsw.push(bXNkNWfNSycsaY);}function j7(nIcnBqdlXMUhrGHA){if(OXDacAy(nIcnBqdlXMUh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}