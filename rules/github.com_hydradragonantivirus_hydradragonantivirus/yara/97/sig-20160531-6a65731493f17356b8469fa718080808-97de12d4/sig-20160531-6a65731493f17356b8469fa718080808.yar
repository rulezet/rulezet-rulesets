rule sig_20160531_6a65731493f17356b8469fa718080808 {
  meta:
    description = "datamaliciousorder - file 20160531_6a65731493f17356b8469fa718080808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98dc8bed2242249e2f37c660ce95ba1c1f066b51287125f3a8a772cb0d2b08d6"

  strings:
    $s1  = "var ZspTzwTk=function(){return WScript.CreateObject(oitPohpKIVIeGSmAlJrp[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function FFUJLlMfyZO(GFQMLOcgyAqYgKEBV,hZKlMqeMejRaYBY){return GFQMLOcgyAqYgKEBV.charAt(hZKlMqeMejRaYBY);}" fullword ascii
    $s3  = "function gFeLtXKDDPF(QXctPirchtBSnCZxSYHnktf,iPVRKmHKjGYdws){return QXctPirchtBSnCZxSYHnktf.indexOf(iPVRKmHKjGYdws);}" fullword ascii
    $s4  = "vP>> 8 & 0xff;MVdrdB = yDrHEvP & 0xff;if (rzKdsgJWGxLLtXeHejAxBL == 64) JNsimSQzpVd += Pjm(QwBplCZNXhXncIysiU);else if (rzTngMnh" ascii
    $s5  = "function mZZoqzFW(KzzUNnnemF,kknQFpMWxGjc,XpmdaWofMeUyEcBDPlVXxKse){return String.fromCharCode(KzzUNnnemF,kknQFpMWxGjc,XpmdaWofM" ascii
    $s6  = "function GmMIFgBCNbIY(){return yayhPJPSDM(oitPohpKIVIeGSmAlJrp[11],[2,4,8,10],oitPohpKIVIeGSmAlJrp[12]);}" fullword ascii
    $s7  = "function aIQTzMcZzi(){return yayhPJPSDM(oitPohpKIVIeGSmAlJrp[13],[0,3,6],oitPohpKIVIeGSmAlJrp[14]);}" fullword ascii
    $s8  = "Line(zwFAzDi);GSQvncCi.Close();}" fullword ascii
    $s9  = "function ToTpdjF(USMjHQRivuSi,uxWlP) {var hnAeFCJlJ=[oitPohpKIVIeGSmAlJrp[15]];USMjHQRivuSi[hnAeFCJlJ[0]]" fullword ascii
    $s10 = "function Pjm(jMzblO){return String.fromCharCode(jMzblO);}" fullword ascii
    $s11 = "function NATfQTjeIeiEyPlUeJq(JvCOeLaZbHPKjecs,pMVpBRlOFVJxsWslfld){return String.fromCharCode(JvCOeLaZbHPKjecs,pMVpBRlOFVJxsWslf" ascii
    $s12 = "TD]];}return KdDBzISJwIb.substring(3,KdDBzISJwIb.length);}" fullword ascii
    $s13 = "function yayhPJPSDM(NgIbrnGWitGQD,MjBXXRFFomWxrd,tUYPLYS){pYrLkjVERd=NgIbrnGWitGQD.split(tUYPLYS);KdDBzISJwIb = oitPohpKIVIeGSmA" ascii
    $s14 = "siU, EmrKyiN, MVdrdB);} while (PIAHbwPC < pUgqpAstpGZOa.length);return JNsimSQzpVd;}" fullword ascii
    $s15 = "var LNVrjDLM=function(){return new ActiveXObject(oitPohpKIVIeGSmAlJrp[1]);}();" fullword ascii
    $s16 = "function NATfQTjeIeiEyPlUeJq(JvCOeLaZbHPKjecs,pMVpBRlOFVJxsWslfld){return String.fromCharCode(JvCOeLaZbHPKjecs,pMVpBRlOFVJxsWslf" ascii
    $s17 = "(uxWlP,0x1,0x0)}function DvZtwmuSClt(JBhWxL,fbKUcWCyy,zwFAzDi){var GSQvncCi=JBhWxL.createtextfile(fbKUcWCyy,true);GSQvncCi.Write" ascii
    $s18 = "(uxWlP,0x1,0x0)}function DvZtwmuSClt(JBhWxL,fbKUcWCyy,zwFAzDi){var GSQvncCi=JBhWxL.createtextfile(fbKUcWCyy,true);GSQvncCi.Write" ascii
    $s19 = "function yayhPJPSDM(NgIbrnGWitGQD,MjBXXRFFomWxrd,tUYPLYS){pYrLkjVERd=NgIbrnGWitGQD.split(tUYPLYS);KdDBzISJwIb = oitPohpKIVIeGSmA" ascii
    $s20 = "function ltdzbmJzVBe(pUgqpAstpGZOa) {var DrDqA = KQXjFJfJyVBebFcBOlaFOPZ.join(oitPohpKIVIeGSmAlJrp[7]);var QwBplCZNXhXncIysiU, E" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}