rule sig_20151210_9dbb8e2ff49b0f9c7e4d4fc59a08a0c0 {
  meta:
    description = "datamaliciousorder - file 20151210_9dbb8e2ff49b0f9c7e4d4fc59a08a0c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d5e86835ef5ffb5e735aeb48c47a2552d2959ccf46e4f6753ae80ddf1cfd883"

  strings:
    $s1  = "function vqMOnzd(WVYfALxVdmfZMCsPWIBLqkDpESDWFlesTMzd) {return !isNaN(parseFloat(WVYfALxVdmfZMCsPWIBLqkDpESDWFlesTMzd)) && isFin" ascii
    $s2  = "function vqMOnzd(WVYfALxVdmfZMCsPWIBLqkDpESDWFlesTMzd) {return !isNaN(parseFloat(WVYfALxVdmfZMCsPWIBLqkDpESDWFlesTMzd)) && isFin" ascii
    $s3  = "function KsArEbdMcWCBJBElM(vaNDJ){GdlEeKMPNVc= '';for(kMXKFkZMcjg=(-872+872)/901; kMXKFkZMcjg < (790+120)/455; kMXKFkZMcjg++) {b" ascii
    $s4  = "function KsArEbdMcWCBJBElM(vaNDJ){GdlEeKMPNVc= '';for(kMXKFkZMcjg=(-872+872)/901; kMXKFkZMcjg < (790+120)/455; kMXKFkZMcjg++) {b" ascii
    $s5  = "function OasJi(SFiZWsMnNds,TgUdAYyrUMqvx,JflrkkXO){blXa=parseInt(SFiZWsMnNds,TgUdAYyrUMqvx);ZfyaK=blXa.toString(JflrkkXO);return" ascii
    $s6  = "function OasJi(SFiZWsMnNds,TgUdAYyrUMqvx,JflrkkXO){blXa=parseInt(SFiZWsMnNds,TgUdAYyrUMqvx);ZfyaK=blXa.toString(JflrkkXO);return" ascii
    $s7  = "function lSsaLwfriKQ(DpdfVBiD,bEyKUG){return DpdfVBiD.split(bEyKUG)}" fullword ascii
    $s8  = " ZfyaK;}function YHsgryVXURxOGRZ(hzoMEYsaOAiHHDegR){eval(hzoMEYsaOAiHHDegR)}" fullword ascii
    $s9  = "function bbkyPfRFcDrfTwUDTqAqAQtVzlAOVJaJhNXYvRLPOkVJXdFtsmgYHq(USMRgixpVpYAF,lINDzhSRuGEqPc){ return GYOui[OasJi(USMRgixpVpYAF[" ascii
    $s10 = "function bbkyPfRFcDrfTwUDTqAqAQtVzlAOVJaJhNXYvRLPOkVJXdFtsmgYHq(USMRgixpVpYAF,lINDzhSRuGEqPc){ return GYOui[OasJi(USMRgixpVpYAF[" ascii
    $s11 = "GizVqPvE[kMXKFkZMcjg]=(-80+80)/388; while(true) { if(bGizVqPvE[kMXKFkZMcjg] > vaNDJ[kMXKFkZMcjg].length-(19+33)/52) { break; } i" ascii
    $s12 = "return GdlEeKMPNVc}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}