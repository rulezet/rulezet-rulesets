rule sig_20160526_e51558e62b525b35823ba7df342da1dc {
  meta:
    description = "datamaliciousorder - file 20160526_e51558e62b525b35823ba7df342da1dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b7856dd2830235ef6bafb1ad7d7ea10c28fbaf817ec10e2445a5b7c9101596"

  strings:
    $s1  = " + Math.pow(Math.cos(903), 2) - 1))-994)) JlnvlQdEAhh += WMt(thPifBG);else if (BmiYIA == (215 + Math.round((Math.pow(Math.sin(24" ascii
    $s2  = "0), 2) + Math.pow(Math.cos(240), 2) - 1))-151)) JlnvlQdEAhh += kdkNclRHILmqzQVeY(thPifBG, volgebhx);else JlnvlQdEAhh += fhQqHJLy" ascii
    $s3  = "function XkaBGN(GtjrnrmZUuFwg) {var CcRXWhCgbeZ = tEKuzLpYUTknwHW.join(LHYmzRfZf[0]);var thPifBG, volgebhx, RwIzCkhlPwcmBVz, rDK" ascii
    $s4  = "function bQltVyqjiW(AVfre,HyoEgklBHW){return AVfre.charAt(HyoEgklBHW);}" fullword ascii
    $s5  = "sqYTWAESBLy(thPifBG, volgebhx, RwIzCkhlPwcmBVz);} while (PHSPwRYTPZciTSLjLkw < GtjrnrmZUuFwg.length);return JlnvlQdEAhh;}" fullword ascii
    $s6  = "function fhQqHJLysqYTWAESBLy(tWwjWMqpobJO,YbZrkSdE,SWIKOIeCObcRYljaPIlaibo){return String.fromCharCode(tWwjWMqpobJO,YbZrkSdE,SWI" ascii
    $s7  = "function fhQqHJLysqYTWAESBLy(tWwjWMqpobJO,YbZrkSdE,SWIKOIeCObcRYljaPIlaibo){return String.fromCharCode(tWwjWMqpobJO,YbZrkSdE,SWI" ascii
    $s8  = "function WMt(pTCOeadMZsJngMtvWuDxqSpe){return String.fromCharCode(pTCOeadMZsJngMtvWuDxqSpe);}" fullword ascii
    $s9  = "function kdkNclRHILmqzQVeY(enDtHEETa,DyWrOjUQqUpTzyBvc){return String.fromCharCode(enDtHEETa,DyWrOjUQqUpTzyBvc);}" fullword ascii
    $s10 = "function PoCWlbZDZUSS(jxvNdGSA,UhjcSdmNkBP){return jxvNdGSA.indexOf(UhjcSdmNkBP);}" fullword ascii
    $s11 = "function XkaBGN(GtjrnrmZUuFwg) {var CcRXWhCgbeZ = tEKuzLpYUTknwHW.join(LHYmzRfZf[0]);var thPifBG, volgebhx, RwIzCkhlPwcmBVz, rDK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}