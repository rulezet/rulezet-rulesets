rule sig_20160527_d0b3d7a69d7b33fcaab6ee63966c2171 {
  meta:
    description = "datamaliciousorder - file 20160527_d0b3d7a69d7b33fcaab6ee63966c2171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3c3b497ef2c3223dbf9777dae657cf727b3fe71925cefe66fd106a453f04a0"

  strings:
    $s1  = "function iGhxsU() {return WScript;}function SZusRPADFb(){return vxHqBjcGslUQR.ExpandEnvironmentStrings(WhXJEzo())}" fullword ascii
    $s2  = "function sFKPZrLhbJWSi(gJGtJVjwqMFUOLIcdmYwFPXy,tLIsJk){return gJGtJVjwqMFUOLIcdmYwFPXy.charAt(tLIsJk);}" fullword ascii
    $s3  = "function rFKnmIxwjahwbNszuLHzSIyN(JrnxzuSaeoDARkulAg,hTCWLKgycarOfsJUlsU){return JrnxzuSaeoDARkulAg.indexOf(hTCWLKgycarOfsJUlsU)" ascii
    $s4  = "function rFKnmIxwjahwbNszuLHzSIyN(JrnxzuSaeoDARkulAg,hTCWLKgycarOfsJUlsU){return JrnxzuSaeoDARkulAg.indexOf(hTCWLKgycarOfsJUlsU)" ascii
    $s5  = "function wcRGvLfRBQdzGQKk(pdDmCBqNmHqauUo,imrCdNaDcxdPAAheDyUVmOwG,ubAhADQQzLMKvOsxfF){return String.fromCharCode(pdDmCBqNmHqauU" ascii
    $s6  = "var vxHqBjcGslUQR=function(){return iGhxsU().CreateObject(qBqFyyrDhboYieWMSekE[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s7  = "function WcuUaJ(){return sWOKeTXgXQjn(qBqFyyrDhboYieWMSekE[12],[0,3,6],qBqFyyrDhboYieWMSekE[13]);}" fullword ascii
    $s8  = "function XFadWJY(OJURHbSNEkXP,KSbvxOQcUYhaWI){return String.fromCharCode(OJURHbSNEkXP,KSbvxOQcUYhaWI);}" fullword ascii
    $s9  = "function RimZwuHvFKLT(){return sWOKeTXgXQjn(qBqFyyrDhboYieWMSekE[10],[2,4,8,10],qBqFyyrDhboYieWMSekE[11]);}" fullword ascii
    $s10 = ");else if (XRZgI == 64) JOVPzzKB += XFadWJY(FvPeSLzakphSOzqNiQyWNBgI, uNCHWInZXYYsdJwkhcYUWx);else JOVPzzKB += wcRGvLfRBQdzGQKk(" ascii
    $s11 = "function sWOKeTXgXQjn(iNBAJ,iQbmidpJoYPAK,AxeUEhviMKOfW){pezHq=iNBAJ.split(AxeUEhviMKOfW);QXAiXKZrApN = qBqFyyrDhboYieWMSekE[14]" ascii
    $s12 = "FvPeSLzakphSOzqNiQyWNBgI, uNCHWInZXYYsdJwkhcYUWx, EvxiYzZEbmGwPhqoNj);} while (ovrKXzule < DaUzFWxlTIEoJ.length);return JOVPzzKB" ascii
    $s13 = "function InMGRzoyYr(HDNSDmXnlSeF,vXTgN) {var hOCTJtlv=[qBqFyyrDhboYieWMSekE[15]];HDNSDmXnlSeF[hOCTJtlv[0]](vXTgN,0x1,0x0)}" fullword ascii
    $s14 = "function Y(xeTgywOPMwUtURDtF){return String.fromCharCode(xeTgywOPMwUtURDtF);}" fullword ascii
    $s15 = "function wcRGvLfRBQdzGQKk(pdDmCBqNmHqauUo,imrCdNaDcxdPAAheDyUVmOwG,ubAhADQQzLMKvOsxfF){return String.fromCharCode(pdDmCBqNmHqauU" ascii
    $s16 = "function sWOKeTXgXQjn(iNBAJ,iQbmidpJoYPAK,AxeUEhviMKOfW){pezHq=iNBAJ.split(AxeUEhviMKOfW);QXAiXKZrApN = qBqFyyrDhboYieWMSekE[14]" ascii
    $s17 = "function WhXJEzo(){return sWOKeTXgXQjn(qBqFyyrDhboYieWMSekE[8],[1,5,7],qBqFyyrDhboYieWMSekE[9]);}" fullword ascii
    $s18 = ";for(ycEArLbehbB=0;ycEArLbehbB<iQbmidpJoYPAK.length;ycEArLbehbB++) {QXAiXKZrApN+=pezHq[iQbmidpJoYPAK[ycEArLbehbB]];}return QXAiX" ascii
    $s19 = ")+String.fromCharCode(92)+qBqFyyrDhboYieWMSekE[4],true);" fullword ascii
    $s20 = "var xoGCAhF = aCCHzUecaojE.createtextfile(vxHqBjcGslUQR.ExpandEnvironmentStrings(qBqFyyrDhboYieWMSekE[2]+qBqFyyrDhboYieWMSekE[3]" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}