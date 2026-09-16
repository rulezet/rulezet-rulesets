rule sig_20160531_6b3918ac4021940f5ed128ed91ff9020 {
  meta:
    description = "datamaliciousorder - file 20160531_6b3918ac4021940f5ed128ed91ff9020.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec2def2c0c062f2586e0c241c41f10d3a6c14fd867fe10a5dcb0bcb2828873c"

  strings:
    $s1  = "var eMwNL=function(){return WScript.CreateObject(jKlGdZjsaKPRqHmmiHlDhT[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function qCaNfg(jGzzVtbnBSaapEFQS,xzuIEOIxgyckCiVahJXHwbg){return jGzzVtbnBSaapEFQS.charAt(xzuIEOIxgyckCiVahJXHwbg);}" fullword ascii
    $s3  = "ZOdbusSlThSEFMAi == 64) VgsLdqEbzjXI += nI(PXWgmGOFWLlmwAKo);else if (rgbFCPwinr == 64) VgsLdqEbzjXI += pwumXbSuNvglJZRohzalYc(P" ascii
    $s4  = "function pwumXbSuNvglJZRohzalYc(XJavKdekdlCNfdX,SJaFOluBpICHiZfJQqE){return String.fromCharCode(XJavKdekdlCNfdX,SJaFOluBpICHiZfJ" ascii
    $s5  = "function PFnGi(SLZRvSdzehWbBV,gbmVLecycueWF,DqDSYJJwlmpzbk){fAWAlcRV=SLZRvSdzehWbBV.split(DqDSYJJwlmpzbk);vGsqTsDaJ = jKlGdZjsaK" ascii
    $s6  = "var odiJHOadI=function(){return new ActiveXObject(jKlGdZjsaKPRqHmmiHlDhT[1]);}();" fullword ascii
    $s7  = "function GXamlJGiBsmOE(){return PFnGi(jKlGdZjsaKPRqHmmiHlDhT[11],[2,4,8,10],jKlGdZjsaKPRqHmmiHlDhT[12]);}" fullword ascii
    $s8  = "function VGGWnqFLNloi(bFzPciDikFfGZwW,ocTVomTZLGiKNBtuGtR,DkpsFscmOwaYRk){return String.fromCharCode(bFzPciDikFfGZwW,ocTVomTZLGi" ascii
    $s9  = "XWgmGOFWLlmwAKo, lqFwyAdOvgWObiwXVO);else VgsLdqEbzjXI += VGGWnqFLNloi(PXWgmGOFWLlmwAKo, lqFwyAdOvgWObiwXVO, hVpaAHPbOWUYhAbejfc" ascii
    $s10 = "function qMpfZywGizf(){return PFnGi(jKlGdZjsaKPRqHmmiHlDhT[9],[1,5,7],jKlGdZjsaKPRqHmmiHlDhT[10]);}" fullword ascii
    $s11 = "function vsEZFoNvVnWd(PqhUkItWPWpIH) {var pBiHDmnRcqKJHuWcuVZHBogf = WHVTxivlJXmcR.join(jKlGdZjsaKPRqHmmiHlDhT[7]);var PXWgmGOFW" ascii
    $s12 = "pzxH);} while (qllhKRnAGpxXsSNdm < PqhUkItWPWpIH.length);return VgsLdqEbzjXI;}" fullword ascii
    $s13 = "function PFnGi(SLZRvSdzehWbBV,gbmVLecycueWF,DqDSYJJwlmpzbk){fAWAlcRV=SLZRvSdzehWbBV.split(DqDSYJJwlmpzbk);vGsqTsDaJ = jKlGdZjsaK" ascii
    $s14 = "function FmWreczkhu(){return eMwNL.ExpandEnvironmentStrings(qMpfZywGizf())}" fullword ascii
    $s15 = "function VGGWnqFLNloi(bFzPciDikFfGZwW,ocTVomTZLGiKNBtuGtR,DkpsFscmOwaYRk){return String.fromCharCode(bFzPciDikFfGZwW,ocTVomTZLGi" ascii
    $s16 = "(bmKmQvzya,0x1,0x0)}function TDZNPNPrteF(lFKmOr,XEXUHXesY,aOnDlESVs){var vOUeZrgYPmNJTP=lFKmOr.createtextfile(XEXUHXesY,true);vO" ascii
    $s17 = "(bmKmQvzya,0x1,0x0)}function TDZNPNPrteF(lFKmOr,XEXUHXesY,aOnDlESVs){var vOUeZrgYPmNJTP=lFKmOr.createtextfile(XEXUHXesY,true);vO" ascii
    $s18 = "function SynUYwku(qEMJVWzrD,nkgxzFZbPNiIywucEbTk){return qEMJVWzrD.indexOf(nkgxzFZbPNiIywucEbTk);}" fullword ascii
    $s19 = "function ENUfvuvJB(IOaIqZCYWpYyuF,bmKmQvzya) {var PlNHWkJv=[jKlGdZjsaKPRqHmmiHlDhT[15]];IOaIqZCYWpYyuF[PlNHWkJv[0]]" fullword ascii
    $s20 = "function pGotSQ(){return PFnGi(jKlGdZjsaKPRqHmmiHlDhT[13],[0,3,6],jKlGdZjsaKPRqHmmiHlDhT[14]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}