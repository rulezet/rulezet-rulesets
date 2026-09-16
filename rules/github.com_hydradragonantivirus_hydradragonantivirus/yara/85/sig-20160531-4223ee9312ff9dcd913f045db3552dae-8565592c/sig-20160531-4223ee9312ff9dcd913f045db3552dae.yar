rule sig_20160531_4223ee9312ff9dcd913f045db3552dae {
  meta:
    description = "datamaliciousorder - file 20160531_4223ee9312ff9dcd913f045db3552dae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e993f77627639981cfcda751267312b218b5830937528973e67676507d481e7b"

  strings:
    $s1  = "var eozYtkRFlsmNw=function(){return WScript.CreateObject(ddpyYNwIxYcCx[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function KxFwVtgqyjOoMAg(rLQPcxaUc,OUWFbN){return rLQPcxaUc.charAt(OUWFbN);}" fullword ascii
    $s3  = "function HI(AZDpuVCNA){return String.fromCharCode(AZDpuVCNA);}" fullword ascii
    $s4  = "bD(sbHkNjTxQR, wPUkQHexbXMW, jHIBBkTKNA);} while (KALzmiNHWsBaeJsImCxhqbbq < BfGcpNJyDnktx.length);return ggbqjUoQpqX;}" fullword ascii
    $s5  = "function TviVPMZlNGjGkzBENN(iqzbWvNiG,wETRcqHJvxDxe){return String.fromCharCode(iqzbWvNiG,wETRcqHJvxDxe);}" fullword ascii
    $s6  = "(YIDenwoOmPgscW,0x1,0x0)}function YyCrkguVkgl(YeHvGDHuUvApV,umMaAXWB,gIbSoOYRrfQBW){var muGdzQdFb=YeHvGDHuUvApV.createtextfile(u" ascii
    $s7  = "function OyrcwomVCy(BfGcpNJyDnktx) {var XpxoQCjYirMrdnnHL = TxMcLAsblZAeHeNLBnVjkJl.join(ddpyYNwIxYcCx[7]);var sbHkNjTxQR, wPUkQ" ascii
    $s8  = "function OzuvXDuAuzZkFUQhCEUbD(PYSfqRSRSuFY,SmiEDtvXnDPXbheErIhBC,uEsRXX){return String.fromCharCode(PYSfqRSRSuFY,SmiEDtvXnDPXbh" ascii
    $s9  = "function OzuvXDuAuzZkFUQhCEUbD(PYSfqRSRSuFY,SmiEDtvXnDPXbheErIhBC,uEsRXX){return String.fromCharCode(PYSfqRSRSuFY,SmiEDtvXnDPXbh" ascii
    $s10 = "function ISNQm(cLCmLiMUd,HTjVZJaCuVlKTrmoNRy){return cLCmLiMUd.indexOf(HTjVZJaCuVlKTrmoNRy);}" fullword ascii
    $s11 = "mMaAXWB,true);muGdzQdFb.WriteLine(gIbSoOYRrfQBW);muGdzQdFb.Close();}" fullword ascii
    $s12 = "function OBszTQXJmEeKDu(){return HGqCx(ddpyYNwIxYcCx[13],[0,3,6],ddpyYNwIxYcCx[14]);}" fullword ascii
    $s13 = "QR);else if (uLcDmEdR == 64) ggbqjUoQpqX += TviVPMZlNGjGkzBENN(sbHkNjTxQR, wPUkQHexbXMW);else ggbqjUoQpqX += OzuvXDuAuzZkFUQhCEU" ascii
    $s14 = "function HGqCx(NRxRlCHRcGA,kFuizwWT,UuTRbhvbVlPXj){jTsrQMVpxR=NRxRlCHRcGA.split(UuTRbhvbVlPXj);uMTSaAfwtBKzOS = ddpyYNwIxYcCx[0]" ascii
    $s15 = "(YIDenwoOmPgscW,0x1,0x0)}function YyCrkguVkgl(YeHvGDHuUvApV,umMaAXWB,gIbSoOYRrfQBW){var muGdzQdFb=YeHvGDHuUvApV.createtextfile(u" ascii
    $s16 = "var jnVvxWC=function(){return new ActiveXObject(ddpyYNwIxYcCx[1]);}();" fullword ascii
    $s17 = "function igfcFgkTsGZBpN(NDEEv,YIDenwoOmPgscW) {var FDQkpdiZg=[ddpyYNwIxYcCx[15]];NDEEv[FDQkpdiZg[0]]" fullword ascii
    $s18 = "function qxYraGgTMIN(){return HGqCx(ddpyYNwIxYcCx[9],[1,5,7],ddpyYNwIxYcCx[10]);}" fullword ascii
    $s19 = "function HGqCx(NRxRlCHRcGA,kFuizwWT,UuTRbhvbVlPXj){jTsrQMVpxR=NRxRlCHRcGA.split(UuTRbhvbVlPXj);uMTSaAfwtBKzOS = ddpyYNwIxYcCx[0]" ascii
    $s20 = "function eHmbPovuNwDrHF(){return HGqCx(ddpyYNwIxYcCx[11],[2,4,8,10],ddpyYNwIxYcCx[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}