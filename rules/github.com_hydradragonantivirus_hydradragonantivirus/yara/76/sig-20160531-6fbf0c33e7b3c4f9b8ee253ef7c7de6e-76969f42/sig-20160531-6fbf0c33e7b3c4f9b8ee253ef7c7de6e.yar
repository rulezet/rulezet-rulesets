rule sig_20160531_6fbf0c33e7b3c4f9b8ee253ef7c7de6e {
  meta:
    description = "datamaliciousorder - file 20160531_6fbf0c33e7b3c4f9b8ee253ef7c7de6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8297589eb7beae0e8d22951d33c084d57ac621974a42abb42ca8b1b4d1dbe28"

  strings:
    $s1  = "var lqjHTPdfJPMML=function(){return WScript.CreateObject(kqvhZxwJiYlLkMl[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mIjNHGn(QwZnSjwZwwNvrUY,wdAlZbJ){return QwZnSjwZwwNvrUY.charAt(wdAlZbJ);}" fullword ascii
    $s3  = "(uDcFcBSAezi,0x1,0x0)}function mhsED(egPyGqfWW,HhMYLB,DWVtKQi){var ZPMJifGSv=egPyGqfWW.createtextfile(HhMYLB,true);ZPMJifGSv.Wri" ascii
    $s4  = "function PJoZnvXvAJpLTGMavvnYjLee(OjGBVZcHNzhXEH,GMZGyRkTlpy){return String.fromCharCode(OjGBVZcHNzhXEH,GMZGyRkTlpy);}" fullword ascii
    $s5  = "function JFwpQWfkUCDetr(){return lqjHTPdfJPMML.ExpandEnvironmentStrings(rpSrQlgQ())}" fullword ascii
    $s6  = "function rGdcWmxAQh(ujcXVr,sRkYYJAmsvx,CcyfNoWG){iDCeMrtbXUfuVR=ujcXVr.split(CcyfNoWG);BzCXkfYJIMft = kqvhZxwJiYlLkMl[0];for(geP" ascii
    $s7  = "function UWaIvyWM(xCBzQFzRb,PoWpSSMhAtjNKQYVbMIdOxSB,qSiqMXXa){return String.fromCharCode(xCBzQFzRb,PoWpSSMhAtjNKQYVbMIdOxSB,qSi" ascii
    $s8  = "function rpSrQlgQ(){return rGdcWmxAQh(kqvhZxwJiYlLkMl[9],[1,5,7],kqvhZxwJiYlLkMl[10]);}" fullword ascii
    $s9  = "function dKqVIWXjumH(spSgEWjSGqhQj) {var ZXTRDoJzLZBqFWXn = IgTtgHXkPhLkMVuuzyIyHZ.join(kqvhZxwJiYlLkMl[7]);var ticOarfJG, AgvCE" ascii
    $s10 = "function wUObFjlJI(){return rGdcWmxAQh(kqvhZxwJiYlLkMl[13],[0,3,6],kqvhZxwJiYlLkMl[14]);}" fullword ascii
    $s11 = "eeRQFxuiZUQ += UWaIvyWM(ticOarfJG, AgvCEpDnYnxNJNEv, LefQHeLVeMTRC);} while (LHjxXmfKLzuYbm < spSgEWjSGqhQj.length);return uOxMW" ascii
    $s12 = "else if (qTphDAbFneHoGTOqTmTNpDU == 64) uOxMWrzeeRQFxuiZUQ += PJoZnvXvAJpLTGMavvnYjLee(ticOarfJG, AgvCEpDnYnxNJNEv);else uOxMWrz" ascii
    $s13 = "function WkNwGDz(){return rGdcWmxAQh(kqvhZxwJiYlLkMl[11],[2,4,8,10],kqvhZxwJiYlLkMl[12]);}" fullword ascii
    $s14 = "function sfBny(tYCOwVFLItAZEpsEQZgdBR,dsUeIsrVRJySqrKl){return tYCOwVFLItAZEpsEQZgdBR.indexOf(dsUeIsrVRJySqrKl);}" fullword ascii
    $s15 = "var nqAjdzmnGMFwIZ=function(){return new ActiveXObject(kqvhZxwJiYlLkMl[1]);}();" fullword ascii
    $s16 = "function UWaIvyWM(xCBzQFzRb,PoWpSSMhAtjNKQYVbMIdOxSB,qSiqMXXa){return String.fromCharCode(xCBzQFzRb,PoWpSSMhAtjNKQYVbMIdOxSB,qSi" ascii
    $s17 = "function dKqVIWXjumH(spSgEWjSGqhQj) {var ZXTRDoJzLZBqFWXn = IgTtgHXkPhLkMVuuzyIyHZ.join(kqvhZxwJiYlLkMl[7]);var ticOarfJG, AgvCE" ascii
    $s18 = "function rGdcWmxAQh(ujcXVr,sRkYYJAmsvx,CcyfNoWG){iDCeMrtbXUfuVR=ujcXVr.split(CcyfNoWG);BzCXkfYJIMft = kqvhZxwJiYlLkMl[0];for(geP" ascii
    $s19 = "(uDcFcBSAezi,0x1,0x0)}function mhsED(egPyGqfWW,HhMYLB,DWVtKQi){var ZPMJifGSv=egPyGqfWW.createtextfile(HhMYLB,true);ZPMJifGSv.Wri" ascii
    $s20 = "function VqkqUo(siRMZr,uDcFcBSAezi) {var cVZoym=[kqvhZxwJiYlLkMl[15]];siRMZr[cVZoym[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}