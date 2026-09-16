rule sig_20160526_5a25f8fbd9ace75e7b3895153e4303d6 {
  meta:
    description = "datamaliciousorder - file 20160526_5a25f8fbd9ace75e7b3895153e4303d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8508d5374afe11a40943c6a2ed202e56fb47098e2a5d3d2ea601f3e4deeba1c"

  strings:
    $s1  = "iZW);else if (PxtjUbdMibXEEfzxezoK == (1025 + Math.round((Math.pow(Math.sin(428), 2) + Math.pow(Math.cos(428), 2) - 1))-961)) Tj" ascii
    $s2  = "sin(216), 2) + Math.pow(Math.cos(216), 2) - 1))-95) | ZWTwOQSrlHghhxlwKBr<< (535 + Math.round((Math.pow(Math.sin(70), 2) + Math." ascii
    $s3  = "function rCCrAUELSoSV(kavkkwsjkRRjK) {var OukIwiamHSgjsQeLaw = UEKDcPF.join(dxyztGdHStoBLCt[0]);var txigPeHOAxDTxhfbYjPTYiZW, So" ascii
    $s4  = "round((Math.pow(Math.sin(469), 2) + Math.pow(Math.cos(469), 2) - 1))-186) | SMZlZiVpGEjTIEoz<< (107 + Math.round((Math.pow(Math." ascii
    $s5  = "function usSCEGxgSaWHNXxVFy(xtmaUzRFxeXOxkGt,uzNSQCGPJ){return xtmaUzRFxeXOxkGt.charAt(uzNSQCGPJ);}" fullword ascii
    $s6  = " ltYDvJqkNIqJDLMUvd(OukIwiamHSgjsQeLaw,usSCEGxgSaWHNXxVFy(kavkkwsjkRRjK,bDRfHCuKqvZE++));tygFsOwUOJpS = rhZLCbgZn<< (204 + Math." ascii
    $s7  = "function rCCrAUELSoSV(kavkkwsjkRRjK) {var OukIwiamHSgjsQeLaw = UEKDcPF.join(dxyztGdHStoBLCt[0]);var txigPeHOAxDTxhfbYjPTYiZW, So" ascii
    $s8  = "function yDWqnrwWSkvIdrM(hoBZMoFGCkESDlodV,mmFMNhNGrGsBxtUZhuG){return String.fromCharCode(hoBZMoFGCkESDlodV,mmFMNhNGrGsBxtUZhuG" ascii
    $s9  = "GrHTnskcYPWnXrMXHw += yDWqnrwWSkvIdrM(txigPeHOAxDTxhfbYjPTYiZW, SoJjCuvzGYvjVNKIo);else TjGrHTnskcYPWnXrMXHw += KenVDyy(txigPeHO" ascii
    $s10 = "AxDTxhfbYjPTYiZW, SoJjCuvzGYvjVNKIo, lWgtKwrE);} while (bDRfHCuKqvZE < kavkkwsjkRRjK.length);return TjGrHTnskcYPWnXrMXHw;}" fullword ascii
    $s11 = "function Sq(sGXcbQHCUZuBDoky){return String.fromCharCode(sGXcbQHCUZuBDoky);}" fullword ascii
    $s12 = "function KenVDyy(BgyPfvYZJlldApyaQaETt,ylCVJFowLUIyyChd,wLWEeHgCxPfpWBZmCeQ){return String.fromCharCode(BgyPfvYZJlldApyaQaETt,yl" ascii
    $s13 = "function ltYDvJqkNIqJDLMUvd(XrSpnLiY,AsSueuzRcEdRYyhDDT){return XrSpnLiY.indexOf(AsSueuzRcEdRYyhDDT);}" fullword ascii
    $s14 = "function yDWqnrwWSkvIdrM(hoBZMoFGCkESDlodV,mmFMNhNGrGsBxtUZhuG){return String.fromCharCode(hoBZMoFGCkESDlodV,mmFMNhNGrGsBxtUZhuG" ascii
    $s15 = "function KenVDyy(BgyPfvYZJlldApyaQaETt,ylCVJFowLUIyyChd,wLWEeHgCxPfpWBZmCeQ){return String.fromCharCode(BgyPfvYZJlldApyaQaETt,yl" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}