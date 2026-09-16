rule sig_20151215_7f9fb415e8c56b943d062aee3377ac76 {
  meta:
    description = "datamaliciousorder - file 20151215_7f9fb415e8c56b943d062aee3377ac76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2212aa658645fccb6ce20d20d786909907a10cf01b3c4fe57f2103aa06994d2a"

  strings:
    $s1  = "Math.pow(Math.cos(554), 2) - 1)); while(true) { if(GZmeWHfyG[fODaYPReLWW] > HloPt[fODaYPReLWW].length-(275+245)/520) { break; } " ascii
    $s2  = "function QnNPVCcfKFZLAuYYg(HloPt){MSPBlRxUBkr= l[1812];for(fODaYPReLWW=Math.round((Math.pow(Math.sin(625), 2) + Math.pow(Math.co" ascii
    $s3  = ".pow(Math.cos(579), 2) - 1)));} GZmeWHfyG[fODaYPReLWW]++;}} return MSPBlRxUBkr}" fullword ascii
    $s4  = "function QnNPVCcfKFZLAuYYg(HloPt){MSPBlRxUBkr= l[1812];for(fODaYPReLWW=Math.round((Math.pow(Math.sin(625), 2) + Math.pow(Math.co" ascii
    $s5  = "ScJlzszTJqBhNMsKcnbkGGvgKOGasyvZpRKO([HloPt[fODaYPReLWW][GZmeWHfyG[fODaYPReLWW]]], Math.round((Math.pow(Math.sin(579), 2) + Math" ascii
    $s6  = "wMNi)) {return (String.fromCharCode(NsEheCKDYvRCwMNi) + String.fromCharCode((17390+370)/296));}}" fullword ascii
    $s7  = "function f(IzBFbTzkKQWh,NehLvGWsKwgigj){IzBFbTzkKQWh.push(NehLvGWsKwgigj);}function g9(NsEheCKDYvRCwMNi){if(CvNBlCl(NsEheCKDYvRC" ascii
    $s8  = "function CvNBlCl(TmqupNTTvvOeqCDbdhRsQJPmhVmEPOvnmxgQ) {return !isNaN(parseFloat(TmqupNTTvvOeqCDbdhRsQJPmhVmEPOvnmxgQ)) && isFin" ascii
    $s9  = "function CvNBlCl(TmqupNTTvvOeqCDbdhRsQJPmhVmEPOvnmxgQ) {return !isNaN(parseFloat(TmqupNTTvvOeqCDbdhRsQJPmhVmEPOvnmxgQ)) && isFin" ascii
    $s10 = "function RFehf(MJyrmHlHTUl,GCuBGYeYwbWHb,rwgqTbmT){thVY=parseInt(MJyrmHlHTUl,GCuBGYeYwbWHb);hBhlM=thVY.toString(rwgqTbmT);return" ascii
    $s11 = "function IlbPTFPZdsGnufkluwScJlzszTJqBhNMsKcnbkGGvgKOGasyvZpRKO(nGdpSGwcyBRCe,LiGvUFmKekpTxp){ return NLqSVhp[wvhwifwE[RFehf(nGd" ascii
    $s12 = "function uioAfjJkJEOuYoV(LseOLfFnLAKfTnzbr){eval(LseOLfFnLAKfTnzbr)}" fullword ascii
    $s13 = "function f(IzBFbTzkKQWh,NehLvGWsKwgigj){IzBFbTzkKQWh.push(NehLvGWsKwgigj);}function g9(NsEheCKDYvRCwMNi){if(CvNBlCl(NsEheCKDYvRC" ascii
    $s14 = "function IlbPTFPZdsGnufkluwScJlzszTJqBhNMsKcnbkGGvgKOGasyvZpRKO(nGdpSGwcyBRCe,LiGvUFmKekpTxp){ return NLqSVhp[wvhwifwE[RFehf(nGd" ascii
    $s15 = "function RFehf(MJyrmHlHTUl,GCuBGYeYwbWHb,rwgqTbmT){thVY=parseInt(MJyrmHlHTUl,GCuBGYeYwbWHb);hBhlM=thVY.toString(rwgqTbmT);return" ascii
    $s16 = "function WSorYkopPyo(ZRkZOrYb,aYCMST){return ZRkZOrYb.split(aYCMST)}" fullword ascii
    $s17 = " hBhlM;}function uioAfjJkJEOuYoV(LseOLfFnLAKfTnzbr,rdZGROPoMrLqjCyXsbAUCClWsAVWXLPJXE,HgrEsjadAjybWXUOoMaSpUjWXQkaGKaaoWO){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}