rule sig_20160526_0269157bb1736360783daaa40d7b8620 {
  meta:
    description = "datamaliciousorder - file 20160526_0269157bb1736360783daaa40d7b8620.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2df0f6970a28c0b7c6aa86d7154663bcd8f7cc8e00c517081180ecad0668f5d"

  strings:
    $s1  = "function GOkFdbFXV(QgxVpOzTnDBmc) {var pmnpEMDZuzkV = xxZqXnKRzk.join(DFlwNwveQFwB[0]);var ORXajWqXRtxOiouEVFeWVeUE, dTgRD, Eppn" ascii
    $s2  = "nd((Math.pow(Math.sin(857), 2) + Math.pow(Math.cos(857), 2) - 1))-105) | ktJHmhApyppaywNpUWA<< (786 + Math.round((Math.pow(Math." ascii
    $s3  = "function gbutPPkcFjQpLkbE(BRHgGTxloGlIGHpEPlN,NcVaQfgqPVOWmrYoZExYr){return BRHgGTxloGlIGHpEPlN.charAt(NcVaQfgqPVOWmrYoZExYr);}" fullword ascii
    $s4  = "function lgxuYiIUUx(OaPwCRrp,VDAYGQvBHQuiKNQybkUgSNk,tURZDScyEOBsZQ){return String.fromCharCode(OaPwCRrp,VDAYGQvBHQuiKNQybkUgSNk" ascii
    $s5  = "function lgxuYiIUUx(OaPwCRrp,VDAYGQvBHQuiKNQybkUgSNk,tURZDScyEOBsZQ){return String.fromCharCode(OaPwCRrp,VDAYGQvBHQuiKNQybkUgSNk" ascii
    $s6  = "function xOlYHUEfnFsjuFebNM(cxSyqcrzGY,piDngMzYBhXzUviMrq){return cxSyqcrzGY.indexOf(piDngMzYBhXzUviMrq);}" fullword ascii
    $s7  = "function t(vMorsHSdWqFFWFIZbKlUEW){return String.fromCharCode(vMorsHSdWqFFWFIZbKlUEW);}" fullword ascii
    $s8  = "ga += YIFcHEcuNpise(ORXajWqXRtxOiouEVFeWVeUE, dTgRD);else NPLFnABGiLhzga += lgxuYiIUUx(ORXajWqXRtxOiouEVFeWVeUE, dTgRD, EppnYsVa" ascii
    $s9  = "function GOkFdbFXV(QgxVpOzTnDBmc) {var pmnpEMDZuzkV = xxZqXnKRzk.join(DFlwNwveQFwB[0]);var ORXajWqXRtxOiouEVFeWVeUE, dTgRD, Eppn" ascii
    $s10 = "rmXTKFObmRk);} while (tSliIom < QgxVpOzTnDBmc.length);return NPLFnABGiLhzga;}" fullword ascii
    $s11 = "function YIFcHEcuNpise(cUFfuMOckSlmDvcZb,MMexpMVgYhKgRWg){return String.fromCharCode(cUFfuMOckSlmDvcZb,MMexpMVgYhKgRWg);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}