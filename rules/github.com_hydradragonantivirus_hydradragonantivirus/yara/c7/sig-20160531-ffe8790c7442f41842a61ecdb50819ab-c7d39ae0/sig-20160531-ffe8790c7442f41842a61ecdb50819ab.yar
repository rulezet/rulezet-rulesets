rule sig_20160531_ffe8790c7442f41842a61ecdb50819ab {
  meta:
    description = "datamaliciousorder - file 20160531_ffe8790c7442f41842a61ecdb50819ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a1907b088831ba477996aa3507558aba90079410d75cddb46000774bdd93d3"

  strings:
    $s1  = "var PpkXvDIsFaffs=function(){return WScript.CreateObject(ktmyRHAuuFTHCZ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function JBzRjwLgRnfNlbJhJiTg(nJmFWVEK,MBklUvhSBxYQsuJsDH){return nJmFWVEK.charAt(MBklUvhSBxYQsuJsDH);}" fullword ascii
    $s3  = "function otqJnn(nbtOnnZ,ZMaemRgI,AWRlZIZGwYA){ORuNVKnnr=nbtOnnZ.split(AWRlZIZGwYA);xkjWDkXBERdFq = ktmyRHAuuFTHCZ[0];for(vjxCiGp" ascii
    $s4  = "function otqJnn(nbtOnnZ,ZMaemRgI,AWRlZIZGwYA){ORuNVKnnr=nbtOnnZ.split(AWRlZIZGwYA);xkjWDkXBERdFq = ktmyRHAuuFTHCZ[0];for(vjxCiGp" ascii
    $s5  = "JhA=0;vjxCiGpJhA<ZMaemRgI.length;vjxCiGpJhA++) {xkjWDkXBERdFq+=ORuNVKnnr[ZMaemRgI[vjxCiGpJhA]];}return xkjWDkXBERdFq.substring(3" ascii
    $s6  = "(hQVONINZIrJOqT,0x1,0x0)}function Pxrxh(fINOQeRrFy,IGtRFmop,XFVKH){var GSLHdiztX=fINOQeRrFy.createtextfile(IGtRFmop,true);GSLHdi" ascii
    $s7  = "function yyRGmHOUjEb(){return otqJnn(ktmyRHAuuFTHCZ[13],[0,3,6],ktmyRHAuuFTHCZ[14]);}" fullword ascii
    $s8  = "function xswZjiqNiflRFAbCPjD(GCzLKDTy,lYEWXpWaafq){return GCzLKDTy.indexOf(lYEWXpWaafq);}" fullword ascii
    $s9  = "function pJkQuPae(zcPtJZMfZjJjE) {var oKobYPQLEyp = sajXDCkA.join(ktmyRHAuuFTHCZ[7]);var LmMoUwOvbtUJJslCyC, bMHqeUIrJYa, pqWDsw" ascii
    $s10 = "function THFvmc(){return otqJnn(ktmyRHAuuFTHCZ[11],[2,4,8,10],ktmyRHAuuFTHCZ[12]);}" fullword ascii
    $s11 = "var jTVhoI=function(){return new ActiveXObject(ktmyRHAuuFTHCZ[1]);}();" fullword ascii
    $s12 = "LmMoUwOvbtUJJslCyC, bMHqeUIrJYa, pqWDswifytBBQwPunl);} while (LgGUGYx < zcPtJZMfZjJjE.length);return iPKdTEnaWb;}" fullword ascii
    $s13 = "function fgzSs(){return PpkXvDIsFaffs.ExpandEnvironmentStrings(QcwygnLgBmpIy())}" fullword ascii
    $s14 = "function QsTCIVvBDvjS(MUqcDztRg,XiHELKWHdReh,FCRtQikqTsZeFmt){return String.fromCharCode(MUqcDztRg,XiHELKWHdReh,FCRtQikqTsZeFmt)" ascii
    $s15 = "function QVbdvGjXkHKySh(HSmNQyRis,hQVONINZIrJOqT) {var KdqpXfcxHVn=[ktmyRHAuuFTHCZ[15]];HSmNQyRis[KdqpXfcxHVn[0]]" fullword ascii
    $s16 = "oUwOvbtUJJslCyC);else if (JNWzEu == 64) iPKdTEnaWb += ILvNXvpe(LmMoUwOvbtUJJslCyC, bMHqeUIrJYa);else iPKdTEnaWb += QsTCIVvBDvjS(" ascii
    $s17 = "function QcwygnLgBmpIy(){return otqJnn(ktmyRHAuuFTHCZ[9],[1,5,7],ktmyRHAuuFTHCZ[10]);}" fullword ascii
    $s18 = "function ILvNXvpe(kvFJRXaXkqfykBH,AljGIHlPZOdjeGoTSuotwtF){return String.fromCharCode(kvFJRXaXkqfykBH,AljGIHlPZOdjeGoTSuotwtF);}" ascii
    $s19 = "(hQVONINZIrJOqT,0x1,0x0)}function Pxrxh(fINOQeRrFy,IGtRFmop,XFVKH){var GSLHdiztX=fINOQeRrFy.createtextfile(IGtRFmop,true);GSLHdi" ascii
    $s20 = "function Ne(oWKcfSP){return String.fromCharCode(oWKcfSP);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}