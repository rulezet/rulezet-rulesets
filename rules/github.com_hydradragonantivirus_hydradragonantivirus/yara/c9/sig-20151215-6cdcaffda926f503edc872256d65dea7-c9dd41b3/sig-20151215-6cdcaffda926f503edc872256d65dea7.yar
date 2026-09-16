rule sig_20151215_6cdcaffda926f503edc872256d65dea7 {
  meta:
    description = "datamaliciousorder - file 20151215_6cdcaffda926f503edc872256d65dea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbe20985b79da03b6009dbd2ab9c728bef39abf08b670132f1d8a7119dd37b39"

  strings:
    $s1  = "function lgmzwmwdzDTgIzsXG(iIaKI){axHqVdWxbXx= x[1814];for(WCaRiEeMOYT=Math.round((Math.pow(Math.sin(876), 2) + Math.pow(Math.co" ascii
    $s2  = "ow(Math.cos(933), 2) - 1)));} Vejeeyrye[WCaRiEeMOYT]++;}} return axHqVdWxbXx}" fullword ascii
    $s3  = "th.pow(Math.cos(99), 2) - 1)); while(true) { if(Vejeeyrye[WCaRiEeMOYT] > iIaKI[WCaRiEeMOYT].length-(335+601)/936) { break; } if " ascii
    $s4  = "kWlA)) {return (String.fromCharCode(kcvSsEdaLQmlkWlA) + String.fromCharCode((28047+381)/618));}}" fullword ascii
    $s5  = "function d(dhYdHyqhDKXP,FJYubCEXmvtbnp){dhYdHyqhDKXP.push(FJYubCEXmvtbnp);}function H5(kcvSsEdaLQmlkWlA){if(pGBeFFl(kcvSsEdaLQml" ascii
    $s6  = "function lgmzwmwdzDTgIzsXG(iIaKI){axHqVdWxbXx= x[1814];for(WCaRiEeMOYT=Math.round((Math.pow(Math.sin(876), 2) + Math.pow(Math.co" ascii
    $s7  = "var x=new Array();" fullword ascii
    $s8  = "function LlOtrwABXfM(eVdHmbOR,wpsefE){return eVdHmbOR.split(wpsefE)}" fullword ascii
    $s9  = "function HxusekBVLjfWdvIctPNqepvWeSCWFxxCPTEGzYYPpnPONywfrsBMUp(FJwbTNUmIGRqU,IEXNgabisYtAle){ return sAHmweg[MLQVPeuU[Gidch(FJw" ascii
    $s10 = "function QLXHsZAxXdkrkvd(uiWrDVJNRqWLOUujT){eval(uiWrDVJNRqWLOUujT)}" fullword ascii
    $s11 = " HmLUm;}function QLXHsZAxXdkrkvd(uiWrDVJNRqWLOUujT,JZeCOdcqRhNWrVRUctYtzoGvrLUPvaYQMH,DddXVRLBDlhwlbMVvQEZClUuhXQyYnrnkPE){eval(" ascii
    $s12 = "function Gidch(sGjDoVdKbWf,IIZXIrLcqwLgA,JvZdSkoh){EywK=parseInt(sGjDoVdKbWf,IIZXIrLcqwLgA);HmLUm=EywK.toString(JvZdSkoh);return" ascii
    $s13 = "function HxusekBVLjfWdvIctPNqepvWeSCWFxxCPTEGzYYPpnPONywfrsBMUp(FJwbTNUmIGRqU,IEXNgabisYtAle){ return sAHmweg[MLQVPeuU[Gidch(FJw" ascii
    $s14 = "function Gidch(sGjDoVdKbWf,IIZXIrLcqwLgA,JvZdSkoh){EywK=parseInt(sGjDoVdKbWf,IIZXIrLcqwLgA);HmLUm=EywK.toString(JvZdSkoh);return" ascii
    $s15 = "function d(dhYdHyqhDKXP,FJYubCEXmvtbnp){dhYdHyqhDKXP.push(FJYubCEXmvtbnp);}function H5(kcvSsEdaLQmlkWlA){if(pGBeFFl(kcvSsEdaLQml" ascii
    $s16 = "function pGBeFFl(FSslwioEZpeZCqCatKlIgtEwlLvrZXrZfsIb) {return !isNaN(parseFloat(FSslwioEZpeZCqCatKlIgtEwlLvrZXrZfsIb)) && isFin" ascii
    $s17 = "function pGBeFFl(FSslwioEZpeZCqCatKlIgtEwlLvrZXrZfsIb) {return !isNaN(parseFloat(FSslwioEZpeZCqCatKlIgtEwlLvrZXrZfsIb)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}