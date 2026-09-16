rule sig_20151216_0537f87de70ae949f7dc6c94a89ae71e {
  meta:
    description = "datamaliciousorder - file 20151216_0537f87de70ae949f7dc6c94a89ae71e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28719064c63f5e944324d684f6b83a0943608c24e2f0ed260aaf1fc9da8c65ae"

  strings:
    $s1  = "Math.cos(367), 2) - 1)));} DLAvYBOKC[CybuVvMudvW]++;}CybuVvMudvW++;} return sSsZztgwcwk}" fullword ascii
    $s2  = "function iHeCSBOhwVuxcOeia(yFJbx){sSsZztgwcwk= '';CybuVvMudvW=Math.round((Math.pow(Math.sin(434), 2) + Math.pow(Math.cos(434), 2" ascii
    $s3  = ") - 1));while(true){if (CybuVvMudvW >= (4010+652)/777){break;}DLAvYBOKC[CybuVvMudvW]=Math.round((Math.pow(Math.sin(83), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(83), 2) - 1)); while(true) { if(DLAvYBOKC[CybuVvMudvW] > yFJbx[CybuVvMudvW].length-(265+80)/345) { break; } if (p" ascii
    $s5  = "function iHeCSBOhwVuxcOeia(yFJbx){sSsZztgwcwk= '';CybuVvMudvW=Math.round((Math.pow(Math.sin(434), 2) + Math.pow(Math.cos(434), 2" ascii
    $s6  = "function puZXdvc(fBsrUojxeTScXavIWOJtDcuLQOfmzWbakAgF) {return !cRkGIQuojXS(GkfSmjVKHntIwAW(fBsrUojxeTScXavIWOJtDcuLQOfmzWbakAgF" ascii
    $s7  = "function iLAWZ(KHbKtmjDZUj,mKsrOgfGdBuiT,nBnFTYFv){rIWS=WtCWfmeNexQFkkxvb(KHbKtmjDZUj,mKsrOgfGdBuiT);jEpJD=rIWS.toString(nBnFTYF" ascii
    $s8  = "function pfhmvjZflVbJNHMJRfrKUUvseHoNcLjQBnbfaegQUwHNcbFnamUGHS(FpNjkzDRqqIsG,lETbXAHxwDaeda){ return BJrEwQl[hSkVNhgy[iLAWZ(FpN" ascii
    $s9  = "v);return jEpJD;}" fullword ascii
    $s10 = "function iLAWZ(KHbKtmjDZUj,mKsrOgfGdBuiT,nBnFTYFv){rIWS=WtCWfmeNexQFkkxvb(KHbKtmjDZUj,mKsrOgfGdBuiT);jEpJD=rIWS.toString(nBnFTYF" ascii
    $s11 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s12 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s13 = "function y(QpVlQtnTYtcelI,NncPBtJtkkaGH,kfkAizNcQvJ) {QpVlQtnTYtcelI[NncPBtJtkkaGH]=kfkAizNcQvJ;}" fullword ascii
    $s14 = "function T(jcQdvEXDTdeH,hVlzUYdSjBvxCP){jcQdvEXDTdeH.push(hVlzUYdSjBvxCP);}" fullword ascii
    $s15 = "function pfhmvjZflVbJNHMJRfrKUUvseHoNcLjQBnbfaegQUwHNcbFnamUGHS(FpNjkzDRqqIsG,lETbXAHxwDaeda){ return BJrEwQl[hSkVNhgy[iLAWZ(FpN" ascii
    $s16 = "function puZXdvc(fBsrUojxeTScXavIWOJtDcuLQOfmzWbakAgF) {return !cRkGIQuojXS(GkfSmjVKHntIwAW(fBsrUojxeTScXavIWOJtDcuLQOfmzWbakAgF" ascii
    $s17 = "function mdPfuPpEETWc(RyKZSwflRatmD) {return isFinite(RyKZSwflRatmD);}" fullword ascii
    $s18 = "function HWOCDUOdgBIiMOT(CEuPRZmWTlCiXApfL,ByHWqVTFRYowevSzITWMixSjuqYiJGGYIE,ZKWiZRIohkCYdSeUVcJaBhWjeocEnpnFCHM){eval(CEuPRZmW" ascii
    $s19 = "function cRkGIQuojXS(IXCUnrzHZJJCTK) {return isNaN(IXCUnrzHZJJCTK);}" fullword ascii
    $s20 = "function HWOCDUOdgBIiMOT(CEuPRZmWTlCiXApfL,ByHWqVTFRYowevSzITWMixSjuqYiJGGYIE,ZKWiZRIohkCYdSeUVcJaBhWjeocEnpnFCHM){eval(CEuPRZmW" ascii

  condition:
    uint16(0) == 0x5368 and
    8 of them
}