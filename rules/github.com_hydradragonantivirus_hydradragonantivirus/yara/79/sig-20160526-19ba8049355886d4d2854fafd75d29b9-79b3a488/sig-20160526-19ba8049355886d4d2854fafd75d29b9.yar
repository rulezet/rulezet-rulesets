rule sig_20160526_19ba8049355886d4d2854fafd75d29b9 {
  meta:
    description = "datamaliciousorder - file 20160526_19ba8049355886d4d2854fafd75d29b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d4d51ef2a7d2bbcdafc9bb12c48d1f5045921c9d0b645e3fdf4491c65ec8de3"

  strings:
    $s1  = "function YPisWVoMHH(uVvAQELKxmsPQ) {var VXgyQS = PNJzOOypQrjoE.join(gOtRvNjE[0]);var aljeuogNaCoVPmTGjvwSVNu, giGTfKCCpJuJDCoMnv" ascii
    $s2  = "nd((Math.pow(Math.sin(25), 2) + Math.pow(Math.cos(25), 2) - 1))-991)) RZlHFSCreRNOTunVIv += Y(aljeuogNaCoVPmTGjvwSVNu);else if (" ascii
    $s3  = "jUkZfijnfkw == (611 + Math.round((Math.pow(Math.sin(957), 2) + Math.pow(Math.cos(957), 2) - 1))-547)) RZlHFSCreRNOTunVIv += niZY" ascii
    $s4  = "function VuMBg(LAGZtPKwkjWPPBNDqGvsYhh,fRMDPpiPPWgzEjDdNmBCCTRW){return LAGZtPKwkjWPPBNDqGvsYhh.charAt(fRMDPpiPPWgzEjDdNmBCCTRW)" ascii
    $s5  = "function VuMBg(LAGZtPKwkjWPPBNDqGvsYhh,fRMDPpiPPWgzEjDdNmBCCTRW){return LAGZtPKwkjWPPBNDqGvsYhh.charAt(fRMDPpiPPWgzEjDdNmBCCTRW)" ascii
    $s6  = "fijnfkw = RqAJmlYfUoZjFcLilWofdgsV(VXgyQS,VuMBg(uVvAQELKxmsPQ,qMkqtGDSFt++));ARTMkOPVsdAYcKEpOc = oOxOneYTRxHUWev<< (1001 + Math" ascii
    $s7  = "function YPisWVoMHH(uVvAQELKxmsPQ) {var VXgyQS = PNJzOOypQrjoE.join(gOtRvNjE[0]);var aljeuogNaCoVPmTGjvwSVNu, giGTfKCCpJuJDCoMnv" ascii
    $s8  = "uEkhJgYyIMiNuXSUc(aljeuogNaCoVPmTGjvwSVNu, giGTfKCCpJuJDCoMnvvG);else RZlHFSCreRNOTunVIv += MVYOyhskxcvXW(aljeuogNaCoVPmTGjvwSVN" ascii
    $s9  = "u, giGTfKCCpJuJDCoMnvvG, TiAJTpQYYmGosO);} while (qMkqtGDSFt < uVvAQELKxmsPQ.length);return RZlHFSCreRNOTunVIv;}" fullword ascii
    $s10 = "function MVYOyhskxcvXW(rSFogYYUiwPbfVENRA,EvNWeGehwpIfqCJqBXeeMwW,XkvhX){return String.fromCharCode(rSFogYYUiwPbfVENRA,EvNWeGehw" ascii
    $s11 = "function niZYuEkhJgYyIMiNuXSUc(URgRSoDSWcoQMzUEYWxrdezB,IFMTcOJViW){return String.fromCharCode(URgRSoDSWcoQMzUEYWxrdezB,IFMTcOJV" ascii
    $s12 = "function Y(UKSNX){return String.fromCharCode(UKSNX);}" fullword ascii
    $s13 = "function RqAJmlYfUoZjFcLilWofdgsV(PDpeFBZehnKqdBmqMrDP,lNMerkVpTZJzguNwsfKpnn){return PDpeFBZehnKqdBmqMrDP.indexOf(lNMerkVpTZJzg" ascii
    $s14 = "function RqAJmlYfUoZjFcLilWofdgsV(PDpeFBZehnKqdBmqMrDP,lNMerkVpTZJzguNwsfKpnn){return PDpeFBZehnKqdBmqMrDP.indexOf(lNMerkVpTZJzg" ascii
    $s15 = "function MVYOyhskxcvXW(rSFogYYUiwPbfVENRA,EvNWeGehwpIfqCJqBXeeMwW,XkvhX){return String.fromCharCode(rSFogYYUiwPbfVENRA,EvNWeGehw" ascii
    $s16 = "function niZYuEkhJgYyIMiNuXSUc(URgRSoDSWcoQMzUEYWxrdezB,IFMTcOJViW){return String.fromCharCode(URgRSoDSWcoQMzUEYWxrdezB,IFMTcOJV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}