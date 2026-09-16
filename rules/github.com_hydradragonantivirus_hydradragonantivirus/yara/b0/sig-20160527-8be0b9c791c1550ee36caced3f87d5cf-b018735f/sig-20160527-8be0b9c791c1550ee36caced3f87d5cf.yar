rule sig_20160527_8be0b9c791c1550ee36caced3f87d5cf {
  meta:
    description = "datamaliciousorder - file 20160527_8be0b9c791c1550ee36caced3f87d5cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf3d4b6df8caf9a55539d44b5fbbf4d8308b05aca18401ec5edd56286028bfe"

  strings:
    $s1  = "function RbeeU() {return WScript;}function rHvPfCdvOWMgiU(){return JVhLajenDxH.ExpandEnvironmentStrings(wDEpCrXWVHyJY())}" fullword ascii
    $s2  = "RxRkAVwLC.length;DUJJBg++) {AroYnL+=maHHTqzg[TNEQRxRkAVwLC[DUJJBg]];}return AroYnL.substring(3,AroYnL.length);}" fullword ascii
    $s3  = "function OWekHVNFoZvpWTMulsCAuLx(tsoTDRlKEf,MQwgRPGa){return tsoTDRlKEf.charAt(MQwgRPGa);}" fullword ascii
    $s4  = "function sqVuxAlvZOPHRD(XKsuEMWVCGiJcVDYTBQTzrV,kfeVnyvWeoEhChYLk){return String.fromCharCode(XKsuEMWVCGiJcVDYTBQTzrV,kfeVnyvWeo" ascii
    $s5  = "function esHKZxyYHtpC(tJqtLqKDqTMez,dHUHvZKwDkqaTN) {var fdrCba=[LGAGrpLCpVU[15]];tJqtLqKDqTMez[fdrCba[0]](dHUHvZKwDkqaTN,0x1,0x" ascii
    $s6  = "function EeFrhaTZ(){return EZCurQwGgSPp(LGAGrpLCpVU[10],[2,4,8,10],LGAGrpLCpVU[11]);}" fullword ascii
    $s7  = "function xNQJJeHdstOoj(bppkQldGzJChK) {var RcRiDoUXqIrx = EfCjkbdMJpJDTRPevSwz.join(LGAGrpLCpVU[6]);var dfLGBthpVGdTaEm, iKrmUYF" ascii
    $s8  = "xff;qAotHrETG = tezTwlkavj & 0xff;if (HocGcKzXUXHEQE == 64) ctkJLIASwEdEGsrVPgOO += fh(dfLGBthpVGdTaEm);else if (ivXNQuaZYpdRCCV" ascii
    $s9  = "function EZCurQwGgSPp(JCXJwB,TNEQRxRkAVwLC,qGxVi){maHHTqzg=JCXJwB.split(qGxVi);AroYnL = LGAGrpLCpVU[14];for(DUJJBg=0;DUJJBg<TNEQ" ascii
    $s10 = "function wDEpCrXWVHyJY(){return EZCurQwGgSPp(LGAGrpLCpVU[8],[1,5,7],LGAGrpLCpVU[9]);}" fullword ascii
    $s11 = "function sqVuxAlvZOPHRD(XKsuEMWVCGiJcVDYTBQTzrV,kfeVnyvWeoEhChYLk){return String.fromCharCode(XKsuEMWVCGiJcVDYTBQTzrV,kfeVnyvWeo" ascii
    $s12 = "function fh(ONinzVDGbbHgNq){return String.fromCharCode(ONinzVDGbbHgNq);}" fullword ascii
    $s13 = "var JVhLajenDxH=function(){return RbeeU().CreateObject(LGAGrpLCpVU[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s14 = "S == 64) ctkJLIASwEdEGsrVPgOO += sqVuxAlvZOPHRD(dfLGBthpVGdTaEm, iKrmUYFqNwalJWW);else ctkJLIASwEdEGsrVPgOO += jrkLjKegtecmImi(d" ascii
    $s15 = "function jrkLjKegtecmImi(WvVLOuBRpaeaQAzoLmX,lQsSplyllAGyaycrEclBzL,NLzggBjSaJLkAghCiKBNxGTV){return String.fromCharCode(WvVLOuB" ascii
    $s16 = "function oEQiAdObhAKFEmENmgeAQlpd(iHydcrHfofRusD,dUXvEWSbHpHUrWGNs){return iHydcrHfofRusD.indexOf(dUXvEWSbHpHUrWGNs);}" fullword ascii
    $s17 = "fLGBthpVGdTaEm, iKrmUYFqNwalJWW, qAotHrETG);} while (MRvdraIuwW < bppkQldGzJChK.length);return ctkJLIASwEdEGsrVPgOO;}" fullword ascii
    $s18 = "function nUFoZqJsMwDq(){return EZCurQwGgSPp(LGAGrpLCpVU[12],[0,3,6],LGAGrpLCpVU[13]);}" fullword ascii
    $s19 = "function esHKZxyYHtpC(tJqtLqKDqTMez,dHUHvZKwDkqaTN) {var fdrCba=[LGAGrpLCpVU[15]];tJqtLqKDqTMez[fdrCba[0]](dHUHvZKwDkqaTN,0x1,0x" ascii
    $s20 = "harCode(92)+LGAGrpLCpVU[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}