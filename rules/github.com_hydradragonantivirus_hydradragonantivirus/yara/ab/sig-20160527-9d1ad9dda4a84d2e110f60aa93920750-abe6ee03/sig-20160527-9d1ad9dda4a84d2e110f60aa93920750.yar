rule sig_20160527_9d1ad9dda4a84d2e110f60aa93920750 {
  meta:
    description = "datamaliciousorder - file 20160527_9d1ad9dda4a84d2e110f60aa93920750.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "761d3d129cf1d3823d45f3b41b53a63f6fbf81221e963a19f1e17fb71d7ccae5"

  strings:
    $s1  = "function ZlUfq() {return WScript;}function CmippfubWdESnP(){return dVuDCOj.ExpandEnvironmentStrings(CYWrjIcXTJ())}" fullword ascii
    $s2  = "function kySmbyDFM(goEqsaOSvupuRg,MHduRvOPgvsjirHJG){return goEqsaOSvupuRg.charAt(MHduRvOPgvsjirHJG);}" fullword ascii
    $s3  = "das);else if (bPnoIwjfUGUPC == 64) gFkNeRliuFwqWII += mvSKkoTQEVtn(sImShyqtzGTEGLAXNrQdas, boEQCV);else gFkNeRliuFwqWII += VgzNq" ascii
    $s4  = "var dBbmYvmsMNxno = EHMxkKeK.createtextfile(dVuDCOj.ExpandEnvironmentStrings(COWSFyuor[2]+COWSFyuor[3])+String.fromCharCode(92)+" ascii
    $s5  = "MBUUPElpbhUwfDy(sImShyqtzGTEGLAXNrQdas, boEQCV, EcIzMSWttXn);} while (JFmhVbJvUgVYKWvVb < hhveDLBQZfkJB.length);return gFkNeRliu" ascii
    $s6  = "function VgzNqMBUUPElpbhUwfDy(fzDVkDkMzcdhX,lmypsdKLnTFGFXKe,eKsumLzbLTgNTsrZQFa){return String.fromCharCode(fzDVkDkMzcdhX,lmyps" ascii
    $s7  = "function KpFUjF(JoDtodqVb,XlKzknlGXh,youqLkXmDJH){gOiDQNRBQzRe=JoDtodqVb.split(youqLkXmDJH);NShmdmeWbpN = COWSFyuor[14];for(rlps" ascii
    $s8  = "function mNXKhAv(zpMrffasJLnLES,kOZIZLZqLY) {var fHFnqYCVK=[COWSFyuor[15]];zpMrffasJLnLES[fHFnqYCVK[0]](kOZIZLZqLY,0x1,0x0)}" fullword ascii
    $s9  = "bUshSHnR=0;rlpsbUshSHnR<XlKzknlGXh.length;rlpsbUshSHnR++) {NShmdmeWbpN+=gOiDQNRBQzRe[XlKzknlGXh[rlpsbUshSHnR]];}return NShmdmeWb" ascii
    $s10 = "function fr(GQcwtOGFZrRapSkAlVZ){return String.fromCharCode(GQcwtOGFZrRapSkAlVZ);}" fullword ascii
    $s11 = "function afFJahepmW(){return KpFUjF(COWSFyuor[10],[2,4,8,10],COWSFyuor[11]);}" fullword ascii
    $s12 = "function KpFUjF(JoDtodqVb,XlKzknlGXh,youqLkXmDJH){gOiDQNRBQzRe=JoDtodqVb.split(youqLkXmDJH);NShmdmeWbpN = COWSFyuor[14];for(rlps" ascii
    $s13 = "function VgzNqMBUUPElpbhUwfDy(fzDVkDkMzcdhX,lmypsdKLnTFGFXKe,eKsumLzbLTgNTsrZQFa){return String.fromCharCode(fzDVkDkMzcdhX,lmyps" ascii
    $s14 = "function oozhkINye(hhveDLBQZfkJB) {var IfuNwohbpOntMR = gTRxXPKCKQRMZVByfmquQATz.join(COWSFyuor[6]);var sImShyqtzGTEGLAXNrQdas, " ascii
    $s15 = "var EHMxkKeK=function(){return new ActiveXObject(COWSFyuor[0]);}();" fullword ascii
    $s16 = "function mvSKkoTQEVtn(DNRaBASbHDMACUGWqQqsdpwp,UyZwdfQia){return String.fromCharCode(DNRaBASbHDMACUGWqQqsdpwp,UyZwdfQia);}" fullword ascii
    $s17 = "function CYWrjIcXTJ(){return KpFUjF(COWSFyuor[8],[1,5,7],COWSFyuor[9]);}" fullword ascii
    $s18 = "push(\"v\");gTRxXPKCKQRMZVByfmquQATz.push(\"w\");gTRxXPKCKQRMZVByfmquQATz.push(\"x\");gTRxXPKCKQRMZVByfmquQATz.push(\"y\");gTRxX" ascii
    $s19 = "COWSFyuor[4],true);" fullword ascii
    $s20 = "function ZluAvtGhaYymaWQs(GkbWZK,eZTKGMsruZvaGPgxubng){return GkbWZK.indexOf(eZTKGMsruZvaGPgxubng);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}