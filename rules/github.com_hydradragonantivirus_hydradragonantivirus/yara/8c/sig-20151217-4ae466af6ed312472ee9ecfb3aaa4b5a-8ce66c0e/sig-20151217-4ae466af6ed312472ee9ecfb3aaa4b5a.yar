rule sig_20151217_4ae466af6ed312472ee9ecfb3aaa4b5a {
  meta:
    description = "datamaliciousorder - file 20151217_4ae466af6ed312472ee9ecfb3aaa4b5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66874755fee75f6070250b747eccbac7b1b8bee04a3b45906c504d466e11240e"

  strings:
    $s1  = "(Math.cos(787), 2) - 1)));} baNyiwHqQ[rhaVOsMnFzS]++;}rhaVOsMnFzS++;} return SYpsGPfkgpx}" fullword ascii
    $s2  = "th.pow(Math.cos(124), 2) - 1)); while(true) { if(baNyiwHqQ[rhaVOsMnFzS] > EnQiz[rhaVOsMnFzS].length-(329+142)/471) { break; } if" ascii
    $s3  = ") - 1));while(true){if (rhaVOsMnFzS >= (2180+742)/487){break;}baNyiwHqQ[rhaVOsMnFzS]=Math.round((Math.pow(Math.sin(124), 2) + Ma" ascii
    $s4  = "function thxjERlaDKgRLHDiu(EnQiz){SYpsGPfkgpx= '';rhaVOsMnFzS=Math.round((Math.pow(Math.sin(130), 2) + Math.pow(Math.cos(130), 2" ascii
    $s5  = "function thxjERlaDKgRLHDiu(EnQiz){SYpsGPfkgpx= '';rhaVOsMnFzS=Math.round((Math.pow(Math.sin(130), 2) + Math.pow(Math.cos(130), 2" ascii
    $s6  = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s7  = "function DRMMQVZvFRJMRVT(xOuXPZAmHOuXrkvZo,wqPIuvNvDMeQfguVLEICdfmaDaeYolHLNM,MECiMqmzRHYXmLOiNBdNWeBTNOYHQRuqddP){eval(xOuXPZAm" ascii
    $s8  = "function L(CFdGzTshhIuj,sBLXHyokUTdWes){CFdGzTshhIuj.push(sBLXHyokUTdWes);}" fullword ascii
    $s9  = "function SHMBKBHcdDfiwIBBy(EjvKOFBUni,TPEWAJMSnC) {return parseInt(EjvKOFBUni,TPEWAJMSnC);}" fullword ascii
    $s10 = "o);return JPnLn;}" fullword ascii
    $s11 = "function nkcvt(XfIsElLEbqV,NAsEdmyjNPTpl,KFlGhjMo){AmHq=SHMBKBHcdDfiwIBBy(XfIsElLEbqV,NAsEdmyjNPTpl);JPnLn=AmHq.toString(KFlGhjM" ascii
    $s12 = "function nkcvt(XfIsElLEbqV,NAsEdmyjNPTpl,KFlGhjMo){AmHq=SHMBKBHcdDfiwIBBy(XfIsElLEbqV,NAsEdmyjNPTpl);JPnLn=AmHq.toString(KFlGhjM" ascii
    $s13 = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s14 = "function DRMMQVZvFRJMRVT(xOuXPZAmHOuXrkvZo,wqPIuvNvDMeQfguVLEICdfmaDaeYolHLNM,MECiMqmzRHYXmLOiNBdNWeBTNOYHQRuqddP){eval(xOuXPZAm" ascii
    $s15 = "function ryEenHJgWvUQ(LywCmhGuzUcMp) {return isFinite(LywCmhGuzUcMp);}" fullword ascii
    $s16 = "function A(ztiOwqhexpmDOc,FczlZMezyJbUI,VYjCYvuHDJE) {ztiOwqhexpmDOc[FczlZMezyJbUI]=VYjCYvuHDJE;}" fullword ascii
    $s17 = "function EYVffKg(ojgmLXJIZfdpGPaistkFzTaUGzjOsXKRnjxk) {return !lMlpKXrCRLZ(cVpUcaatJymXytc(ojgmLXJIZfdpGPaistkFzTaUGzjOsXKRnjxk" ascii
    $s18 = "function lMlpKXrCRLZ(qqMSpSifHTodfP) {return isNaN(qqMSpSifHTodfP);}" fullword ascii
    $s19 = "function pHeKwWwVcvLZNyecLsWGUZYpTlqCaOqCdoAUAUeAHieMipuseZkxIT(YNVMZCBysLrkD,cmscniXnUvQgoU){ return JZKtKXe[NOOqnaZU[nkcvt(YNV" ascii
    $s20 = "function EYVffKg(ojgmLXJIZfdpGPaistkFzTaUGzjOsXKRnjxk) {return !lMlpKXrCRLZ(cVpUcaatJymXytc(ojgmLXJIZfdpGPaistkFzTaUGzjOsXKRnjxk" ascii

  condition:
    uint16(0) == 0x4f4e and
    8 of them
}