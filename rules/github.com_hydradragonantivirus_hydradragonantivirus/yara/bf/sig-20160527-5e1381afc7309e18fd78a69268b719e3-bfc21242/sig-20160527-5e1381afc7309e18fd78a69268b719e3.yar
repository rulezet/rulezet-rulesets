rule sig_20160527_5e1381afc7309e18fd78a69268b719e3 {
  meta:
    description = "datamaliciousorder - file 20160527_5e1381afc7309e18fd78a69268b719e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d40694af9e06f6ea9d3909b2f7cdc730e6074d41320b1b9f5d84a757a82bc24"

  strings:
    $s1  = "function aDlHbXZMrlgrJ() {return WScript;}function qVArKAlzEX(){return tLXGRwwN.ExpandEnvironmentStrings(CCkMOi())}" fullword ascii
    $s2  = "function kSAcrARWDyfvlLaTtpoVaS(EaLiQXBCSC,dBecgdmrdk){return EaLiQXBCSC.charAt(dBecgdmrdk);}" fullword ascii
    $s3  = " sPYMINzU & 0xff;if (NCOdoVFaDST == 64) PJjDGxxU += PJ(aEFeiQQ);else if (UBXAVNYIvVLABRyUjyO == 64) PJjDGxxU += MKQpfqEqWpZXVdWz" ascii
    $s4  = "function HkVyokCv(BPvKXrycAxUWp) {var IftEczApoZagXeehZXJ = WmJOgQUaIkqakxKgZhPrFs.join(MewCxGEFCqMjOvyZt[6]);var aEFeiQQ, SjCwR" ascii
    $s5  = "function eDMFwaaQ(){return pErRG(MewCxGEFCqMjOvyZt[12],[0,3,6],MewCxGEFCqMjOvyZt[13]);}" fullword ascii
    $s6  = "JLNCmQt(aEFeiQQ, SjCwRxiGcznqwXRf);else PJjDGxxU += hgSmTIswUL(aEFeiQQ, SjCwRxiGcznqwXRf, WRmbnXRTNFHzVPIWOHz);} while (qfPmtjT " ascii
    $s7  = "function OspLGHRYMaKNbcJsWDijKD(VggQTMzvyPrgUdOrCUrPJS,uHimDyuHBUPeiEt){return VggQTMzvyPrgUdOrCUrPJS.indexOf(uHimDyuHBUPeiEt);}" ascii
    $s8  = "function pErRG(xPXDyQQK,SwWPdmmo,nNjkEXBmnpJus){IluoYqPxyyT=xPXDyQQK.split(nNjkEXBmnpJus);FHdkkIEQpw = MewCxGEFCqMjOvyZt[14];for" ascii
    $s9  = "var rTkddRSjsCebkq = dppprYS.createtextfile(tLXGRwwN.ExpandEnvironmentStrings(MewCxGEFCqMjOvyZt[2]+MewCxGEFCqMjOvyZt[3])+String." ascii
    $s10 = "fromCharCode(92)+MewCxGEFCqMjOvyZt[4],true);" fullword ascii
    $s11 = "function CCkMOi(){return pErRG(MewCxGEFCqMjOvyZt[8],[1,5,7],MewCxGEFCqMjOvyZt[9]);}" fullword ascii
    $s12 = "function PJ(SFuvgYpcrGUyYGDML){return String.fromCharCode(SFuvgYpcrGUyYGDML);}" fullword ascii
    $s13 = "function MKQpfqEqWpZXVdWzJLNCmQt(XFCsjbAGqMrYu,IiSoolWbbVcTNhxJTuRtLPR){return String.fromCharCode(XFCsjbAGqMrYu,IiSoolWbbVcTNhx" ascii
    $s14 = "function hgSmTIswUL(URWVwsCMNX,FYuvlzFFcvM,JGTpenqZdZxdNDI){return String.fromCharCode(URWVwsCMNX,FYuvlzFFcvM,JGTpenqZdZxdNDI);}" ascii
    $s15 = "function pErRG(xPXDyQQK,SwWPdmmo,nNjkEXBmnpJus){IluoYqPxyyT=xPXDyQQK.split(nNjkEXBmnpJus);FHdkkIEQpw = MewCxGEFCqMjOvyZt[14];for" ascii
    $s16 = "function EYRtGYK(){return pErRG(MewCxGEFCqMjOvyZt[10],[2,4,8,10],MewCxGEFCqMjOvyZt[11]);}" fullword ascii
    $s17 = "var dppprYS=function(){return new ActiveXObject(MewCxGEFCqMjOvyZt[0]);}();" fullword ascii
    $s18 = "(QfGmXclOMCXIAL=0;QfGmXclOMCXIAL<SwWPdmmo.length;QfGmXclOMCXIAL++) {FHdkkIEQpw+=IluoYqPxyyT[SwWPdmmo[QfGmXclOMCXIAL]];}return FH" ascii
    $s19 = "var tLXGRwwN=function(){return aDlHbXZMrlgrJ().CreateObject(MewCxGEFCqMjOvyZt[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function MKQpfqEqWpZXVdWzJLNCmQt(XFCsjbAGqMrYu,IiSoolWbbVcTNhxJTuRtLPR){return String.fromCharCode(XFCsjbAGqMrYu,IiSoolWbbVcTNhx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}