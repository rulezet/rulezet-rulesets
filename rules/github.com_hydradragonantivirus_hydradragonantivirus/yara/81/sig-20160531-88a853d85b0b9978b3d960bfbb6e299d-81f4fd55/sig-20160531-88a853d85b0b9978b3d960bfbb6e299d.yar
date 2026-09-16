rule sig_20160531_88a853d85b0b9978b3d960bfbb6e299d {
  meta:
    description = "datamaliciousorder - file 20160531_88a853d85b0b9978b3d960bfbb6e299d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a9804c9e633daea79d367e88730392840ee67a7862bb3b1d02b6d78726d46ef"

  strings:
    $s1  = "var eTEfCsDFtbdtsk=function(){return WScript.CreateObject(wHGoFtvqDk[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function etsQATPJwNrKg(qNilue,EJDWCOCzjRBGslaziq){return qNilue.charAt(EJDWCOCzjRBGslaziq);}" fullword ascii
    $s3  = "var RsONfOvPDwzh=function(){return new ActiveXObject(wHGoFtvqDk[1]);}();" fullword ascii
    $s4  = "function aoLLCzTmEc(ISADkDirMGfsmKgLcYpFYco,mgBiSCMxnylveaIWtIXwBZEy,XmwjfKNrEEtEtrbpO){return String.fromCharCode(ISADkDirMGfsm" ascii
    $s5  = "function DBrjCNqkEs(){return OAMxAybGHy(wHGoFtvqDk[11],[2,4,8,10],wHGoFtvqDk[12]);}" fullword ascii
    $s6  = "function Ed(huIwZqFysr){return String.fromCharCode(huIwZqFysr);}" fullword ascii
    $s7  = "function HnnuOJXRnoIO(wNNXpxKiokLQFLipkRXfw,AobzoiQ){return String.fromCharCode(wNNXpxKiokLQFLipkRXfw,AobzoiQ);}" fullword ascii
    $s8  = "xff;eytpQdidwVwWVYDK = nPaeLW & 0xff;if (oTEKIAkYBVbUG == 64) uZNfARlbNZkFbL += Ed(VlUgAMehzwZqbJVHt);else if (AsSLsJQqJgmV == 6" ascii
    $s9  = "t, QLfKpwRbTrKICgWZeLnzZCD, eytpQdidwVwWVYDK);} while (qnceEtXJXO < PCGUppjhsgFvM.length);return uZNfARlbNZkFbL;}" fullword ascii
    $s10 = "function aoLLCzTmEc(ISADkDirMGfsmKgLcYpFYco,mgBiSCMxnylveaIWtIXwBZEy,XmwjfKNrEEtEtrbpO){return String.fromCharCode(ISADkDirMGfsm" ascii
    $s11 = "r(DkZfRQerxhoH=0;DkZfRQerxhoH<NPfECUXiKeXN.length;DkZfRQerxhoH++) {YZGacmxFo+=ezUdIgHGpD[NPfECUXiKeXN[DkZfRQerxhoH]];}return YZG" ascii
    $s12 = "function OAMxAybGHy(oMtuTgod,NPfECUXiKeXN,aQrUatTqBzPxnd){ezUdIgHGpD=oMtuTgod.split(aQrUatTqBzPxnd);YZGacmxFo = wHGoFtvqDk[0];fo" ascii
    $s13 = "function ZiZtiPosV(){return eTEfCsDFtbdtsk.ExpandEnvironmentStrings(eEPMqsVe())}" fullword ascii
    $s14 = "function eEPMqsVe(){return OAMxAybGHy(wHGoFtvqDk[9],[1,5,7],wHGoFtvqDk[10]);}" fullword ascii
    $s15 = "4) uZNfARlbNZkFbL += HnnuOJXRnoIO(VlUgAMehzwZqbJVHt, QLfKpwRbTrKICgWZeLnzZCD);else uZNfARlbNZkFbL += aoLLCzTmEc(VlUgAMehzwZqbJVH" ascii
    $s16 = "function kRGUqLAa(jSoyv,lYdgLSDZnRR) {var pEoULUmYDYSYJ=[wHGoFtvqDk[15]];jSoyv[pEoULUmYDYSYJ[0]]" fullword ascii
    $s17 = "function iilpowIvlvChaP(){return OAMxAybGHy(wHGoFtvqDk[13],[0,3,6],wHGoFtvqDk[14]);}" fullword ascii
    $s18 = "function OAMxAybGHy(oMtuTgod,NPfECUXiKeXN,aQrUatTqBzPxnd){ezUdIgHGpD=oMtuTgod.split(aQrUatTqBzPxnd);YZGacmxFo = wHGoFtvqDk[0];fo" ascii
    $s19 = "function GkBxtvoRbzzVu(PCGUppjhsgFvM) {var ODaOxCaclYfeQ = FLtey.join(wHGoFtvqDk[7]);var VlUgAMehzwZqbJVHt, QLfKpwRbTrKICgWZeLnz" ascii
    $s20 = "function GkBxtvoRbzzVu(PCGUppjhsgFvM) {var ODaOxCaclYfeQ = FLtey.join(wHGoFtvqDk[7]);var VlUgAMehzwZqbJVHt, QLfKpwRbTrKICgWZeLnz" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}