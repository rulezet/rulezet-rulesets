rule sig_20151217_ae29cb3f28217089423c85bb42504acb {
  meta:
    description = "datamaliciousorder - file 20151217_ae29cb3f28217089423c85bb42504acb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fcb983bb7d8f128e0f65d2657d752a5c57b0f31f487ba2e60808434f93464aa"

  strings:
    $s1  = "h.pow(Math.cos(620), 2) - 1)); while(true) { if(HTmxihjvg[MbBLhjFVNFw] > IHXgB[MbBLhjFVNFw].length-(-423+698)/275) { break; } if" ascii
    $s2  = ") - 1));while(true){if (MbBLhjFVNFw >= (4705+71)/796){break;}HTmxihjvg[MbBLhjFVNFw]=Math.round((Math.pow(Math.sin(620), 2) + Mat" ascii
    $s3  = "function LHNovjyNFsaycJKkh(IHXgB){LbtoKItqxwF= '';MbBLhjFVNFw=Math.round((Math.pow(Math.sin(319), 2) + Math.pow(Math.cos(319), 2" ascii
    $s4  = "pow(Math.cos(538), 2) - 1)));} HTmxihjvg[MbBLhjFVNFw]++;}MbBLhjFVNFw++;} return LbtoKItqxwF}" fullword ascii
    $s5  = "XMkbDIXKVmhRsZLUtVZahntKhcolKaQpGlt([IHXgB[MbBLhjFVNFw][HTmxihjvg[MbBLhjFVNFw]]], Math.round((Math.pow(Math.sin(538), 2) + Math." ascii
    $s6  = "function LHNovjyNFsaycJKkh(IHXgB){LbtoKItqxwF= '';MbBLhjFVNFw=Math.round((Math.pow(Math.sin(319), 2) + Math.pow(Math.cos(319), 2" ascii
    $s7  = "function GrndMBE(UOomrvNWuesRckswrvkyTyvKolbjLPkiNGFO) {return !zhPLewzDOKG(cjFCMySMTWwbYKH(UOomrvNWuesRckswrvkyTyvKolbjLPkiNGFO" ascii
    $s8  = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s9  = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s10 = "function cjFCMySMTWwbYKH(iXhFnbryZeNaTUDTMvK) {return parseFloat(iXhFnbryZeNaTUDTMvK);}" fullword ascii
    $s11 = "function W(mXaySQeTRCSbpu,yarNVLnYLrcOR,nLTCrDcibMl) {mXaySQeTRCSbpu[yarNVLnYLrcOR]=nLTCrDcibMl;}" fullword ascii
    $s12 = "function GkajK(ztQKRGiItHN,oduhsJTyJaoZH,mgumnMmE){PKBE=fWYunzcrrEiwAgbst(ztQKRGiItHN,oduhsJTyJaoZH);onrhR=PKBE.toString(mgumnMm" ascii
    $s13 = "E);return onrhR;}" fullword ascii
    $s14 = "function PWBEePGBxcbZVHcXowvXMkbDIXKVmhRsZLUtVZahntKhcolKaQpGlt(DQwpWATGvGzOG,SaNdzarognMZVh){ return QEmagGD[lYLoitPT[GkajK(DQw" ascii
    $s15 = "function p(YnMHkkVBgxHg,MeEiqhYBQwJaaD){YnMHkkVBgxHg.push(MeEiqhYBQwJaaD);}" fullword ascii
    $s16 = "function PWBEePGBxcbZVHcXowvXMkbDIXKVmhRsZLUtVZahntKhcolKaQpGlt(DQwpWATGvGzOG,SaNdzarognMZVh){ return QEmagGD[lYLoitPT[GkajK(DQw" ascii
    $s17 = "function PJCmnHbblFaS(mULYmsiFiQCRa) {return isFinite(mULYmsiFiQCRa);}" fullword ascii
    $s18 = "function GrndMBE(UOomrvNWuesRckswrvkyTyvKolbjLPkiNGFO) {return !zhPLewzDOKG(cjFCMySMTWwbYKH(UOomrvNWuesRckswrvkyTyvKolbjLPkiNGFO" ascii
    $s19 = "function fWYunzcrrEiwAgbst(MeKAqCIpjo,nkheDmYKTy) {return parseInt(MeKAqCIpjo,nkheDmYKTy);}" fullword ascii
    $s20 = "function GkajK(ztQKRGiItHN,oduhsJTyJaoZH,mgumnMmE){PKBE=fWYunzcrrEiwAgbst(ztQKRGiItHN,oduhsJTyJaoZH);onrhR=PKBE.toString(mgumnMm" ascii

  condition:
    uint16(0) == 0x596c and
    8 of them
}