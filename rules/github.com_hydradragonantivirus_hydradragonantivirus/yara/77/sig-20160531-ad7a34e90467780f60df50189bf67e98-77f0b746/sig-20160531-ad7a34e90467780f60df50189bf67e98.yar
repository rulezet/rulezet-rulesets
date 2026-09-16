rule sig_20160531_ad7a34e90467780f60df50189bf67e98 {
  meta:
    description = "datamaliciousorder - file 20160531_ad7a34e90467780f60df50189bf67e98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf57717a498e0173deb1f7b417d08ef4a7e02ff62108bf091e923a7e4ebdb9a"

  strings:
    $s1  = "var zvbBOKZ=function(){return WScript.CreateObject(CjmnmJawk[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function GyeONUKWjdxUsXbaItI(TziVvVsdgzeEJoZS,ocMtgsJxhNPBzToG){return TziVvVsdgzeEJoZS.charAt(ocMtgsJxhNPBzToG);}" fullword ascii
    $s3  = "function OltIfZ(xRcEZBaFGBBrH) {var UpZPlODwncMNavuZQScygZ = NuLiotgpRa.join(CjmnmJawk[7]);var zGgsSG, lnnWgrf, IzUTbFJVmDJa, GG" ascii
    $s4  = "function lrASNg(AXIYyEVkom,UaQioFV){return AXIYyEVkom.indexOf(UaQioFV);}" fullword ascii
    $s5  = "function itEEEKzMHGKep(){return pubVJVvvWEEElb(CjmnmJawk[11],[2,4,8,10],CjmnmJawk[12]);}" fullword ascii
    $s6  = "function KqsOrJSQJSjA(QPYCcONzL,JQfCPgTZBqYE) {var mLRnygEOLKNQ=[CjmnmJawk[15]];QPYCcONzL[mLRnygEOLKNQ[0]]" fullword ascii
    $s7  = "function pubVJVvvWEEElb(GVJaTEkT,BPgKtSRILGkhy,azIDboyXvEweUa){aCoeMEvgHhUOWG=GVJaTEkT.split(azIDboyXvEweUa);gtzxgrjH = CjmnmJaw" ascii
    $s8  = "function cMfVUDSYobDcmFKstf(VysnRvNMaNh,pxekaOOzSqqS){return String.fromCharCode(VysnRvNMaNh,pxekaOOzSqqS);}" fullword ascii
    $s9  = "(JQfCPgTZBqYE,0x1,0x0)}function MflrYqZlyhE(FSKJSoS,LRwaYFUXkV,RaunqVyYuZaFgu){var YlDJBq=FSKJSoS.createtextfile(LRwaYFUXkV,true" ascii
    $s10 = "function pubVJVvvWEEElb(GVJaTEkT,BPgKtSRILGkhy,azIDboyXvEweUa){aCoeMEvgHhUOWG=GVJaTEkT.split(azIDboyXvEweUa);gtzxgrjH = CjmnmJaw" ascii
    $s11 = "function SWWJM(ucmiumlgRJRPNmmszI,GMBHXUAZeRuTGDhfCJX,qBRZLXirmR){return String.fromCharCode(ucmiumlgRJRPNmmszI,GMBHXUAZeRuTGDhf" ascii
    $s12 = "function wCKjlu(){return zvbBOKZ.ExpandEnvironmentStrings(jAObToSqDe())}" fullword ascii
    $s13 = "function OltIfZ(xRcEZBaFGBBrH) {var UpZPlODwncMNavuZQScygZ = NuLiotgpRa.join(CjmnmJawk[7]);var zGgsSG, lnnWgrf, IzUTbFJVmDJa, GG" ascii
    $s14 = "f(zGgsSG, lnnWgrf);else VKOIDSkHmluJVXWjFkliNyg += SWWJM(zGgsSG, lnnWgrf, IzUTbFJVmDJa);} while (baUvvJtxxLlSSdjob < xRcEZBaFGBB" ascii
    $s15 = "push(\"K\");NuLiotgpRa.push(\"L\");NuLiotgpRa.push(\"a\");NuLiotgpRa.push(\"b\");NuLiotgpRa.push(\"c\");NuLiotgpRa.push(\"P\");N" ascii
    $s16 = "function oZ(CnrUbD){return String.fromCharCode(CnrUbD);}" fullword ascii
    $s17 = "LKYnBgIhFeqWX == 64) VKOIDSkHmluJVXWjFkliNyg += oZ(zGgsSG);else if (FHnISCXi == 64) VKOIDSkHmluJVXWjFkliNyg += cMfVUDSYobDcmFKst" ascii
    $s18 = "UApqVQ]];}return gtzxgrjH.substring(3,gtzxgrjH.length);}" fullword ascii
    $s19 = "function SWWJM(ucmiumlgRJRPNmmszI,GMBHXUAZeRuTGDhfCJX,qBRZLXirmR){return String.fromCharCode(ucmiumlgRJRPNmmszI,GMBHXUAZeRuTGDhf" ascii
    $s20 = "(JQfCPgTZBqYE,0x1,0x0)}function MflrYqZlyhE(FSKJSoS,LRwaYFUXkV,RaunqVyYuZaFgu){var YlDJBq=FSKJSoS.createtextfile(LRwaYFUXkV,true" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}