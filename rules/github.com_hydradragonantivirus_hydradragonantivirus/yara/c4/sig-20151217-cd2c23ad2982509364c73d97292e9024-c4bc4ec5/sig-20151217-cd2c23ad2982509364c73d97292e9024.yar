rule sig_20151217_cd2c23ad2982509364c73d97292e9024 {
  meta:
    description = "datamaliciousorder - file 20151217_cd2c23ad2982509364c73d97292e9024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50c5c9cd48762051db3a0173e8e52efc0204001775c07d8b027a0e0956533971"

  strings:
    $s1  = "th.pow(Math.cos(377), 2) - 1)); while(true) { if(qAyCVMeRs[rVgoTocdQcp] > FPmCe[rVgoTocdQcp].length-(-623+658)/35) { break; } if" ascii
    $s2  = "ow(Math.cos(704), 2) - 1)));} qAyCVMeRs[rVgoTocdQcp]++;}rVgoTocdQcp++;} return CbBJiBbThNO}" fullword ascii
    $s3  = "function tduGrnyydmVagCxou(FPmCe){CbBJiBbThNO= '';rVgoTocdQcp=Math.round((Math.pow(Math.sin(994), 2) + Math.pow(Math.cos(994), 2" ascii
    $s4  = ") - 1));while(true){if (rVgoTocdQcp >= (2862+462)/554){break;}qAyCVMeRs[rVgoTocdQcp]=Math.round((Math.pow(Math.sin(377), 2) + Ma" ascii
    $s5  = "function wcZHGLh(poSTiciWSrHkMeMObddwVWBNYsjtvfxZjGIa) {return !SaNEvPSRndJ(sTQyADNtGxXjyqu(poSTiciWSrHkMeMObddwVWBNYsjtvfxZjGIa" ascii
    $s6  = "function TXIjpOIfzsYEQrh(QZCXTTkCTADwBNWUC,gKeYEEtgdLGyghYIDdCSIUCCcHZIqsOIua,AMnnvwSaxhLMCyEpHVfOiFXfPNTouTvUJRE){eval(QZCXTTkC" ascii
    $s7  = "function TXIjpOIfzsYEQrh(QZCXTTkCTADwBNWUC,gKeYEEtgdLGyghYIDdCSIUCCcHZIqsOIua,AMnnvwSaxhLMCyEpHVfOiFXfPNTouTvUJRE){eval(QZCXTTkC" ascii
    $s8  = "function tduGrnyydmVagCxou(FPmCe){CbBJiBbThNO= '';rVgoTocdQcp=Math.round((Math.pow(Math.sin(994), 2) + Math.pow(Math.cos(994), 2" ascii
    $s9  = "function wcZHGLh(poSTiciWSrHkMeMObddwVWBNYsjtvfxZjGIa) {return !SaNEvPSRndJ(sTQyADNtGxXjyqu(poSTiciWSrHkMeMObddwVWBNYsjtvfxZjGIa" ascii
    $s10 = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s11 = "function pZEFEZVEoJnr(cJsxHppyjorLF) {return isFinite(cJsxHppyjorLF);}" fullword ascii
    $s12 = "function VlqJH(HvUaSzxtOcG,EzIGlXEmSqJin,KwDJEWsc){ytdW=PDumhuRKNDafqZsZL(HvUaSzxtOcG,EzIGlXEmSqJin);YErny=ytdW.toString(KwDJEWs" ascii
    $s13 = "function Y(GgKXPDQztTau,MxtKhqzvJoKOxx){GgKXPDQztTau.push(MxtKhqzvJoKOxx);}" fullword ascii
    $s14 = "function sTQyADNtGxXjyqu(hoieORHVdmztyTCvtMh) {return parseFloat(hoieORHVdmztyTCvtMh);}" fullword ascii
    $s15 = "function K(pEqXtnJaYjdwxE,oTJpGZhrvVjju,tFKScVqdarp) {pEqXtnJaYjdwxE[oTJpGZhrvVjju]=tFKScVqdarp;}" fullword ascii
    $s16 = "function VlqJH(HvUaSzxtOcG,EzIGlXEmSqJin,KwDJEWsc){ytdW=PDumhuRKNDafqZsZL(HvUaSzxtOcG,EzIGlXEmSqJin);YErny=ytdW.toString(KwDJEWs" ascii
    $s17 = "function UaQFnboisxWAvnKmrnyhcyIsXSQLhMyDONTMlDfFLtIzjVdOgXrWzi(MdundEDWhLXdd,jGPQEktwLBeMNI){ return SgYWBCO[mcnfDBGh[VlqJH(Mdu" ascii
    $s18 = "c);return YErny;}" fullword ascii
    $s19 = "function SaNEvPSRndJ(PgeddoVpddXUsO) {return isNaN(PgeddoVpddXUsO);}" fullword ascii
    $s20 = "function UaQFnboisxWAvnKmrnyhcyIsXSQLhMyDONTMlDfFLtIzjVdOgXrWzi(MdundEDWhLXdd,jGPQEktwLBeMNI){ return SgYWBCO[mcnfDBGh[VlqJH(Mdu" ascii

  condition:
    uint16(0) == 0x636d and
    8 of them
}