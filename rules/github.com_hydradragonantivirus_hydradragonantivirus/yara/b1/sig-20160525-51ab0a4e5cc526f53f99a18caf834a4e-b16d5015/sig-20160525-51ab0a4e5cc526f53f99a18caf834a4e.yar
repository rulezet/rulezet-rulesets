rule sig_20160525_51ab0a4e5cc526f53f99a18caf834a4e {
  meta:
    description = "datamaliciousorder - file 20160525_51ab0a4e5cc526f53f99a18caf834a4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f4b37b6e7a6a2f95a8247b6408d7f8061273b15192f11ee70ace803454c6d24"

  strings:
    $s1  = "function BxDPasZ(fykHJbZRCMmYs) {var HOqAvxoaHgzqcMmgrX = xwRcgSbv.join(SlFWcRIKde[0]);var eGwJjZRfkgGQnWeTeKHTCOOL, eYcBCVryv, " ascii
    $s2  = "193), 2) + Math.pow(Math.cos(193), 2) - 1))-98)) YGCKODpLZ += EYGHACKmRTCKNpb(eGwJjZRfkgGQnWeTeKHTCOOL, eYcBCVryv);else YGCKODpL" ascii
    $s3  = "), 2) - 1))-322)) YGCKODpLZ += YH(eGwJjZRfkgGQnWeTeKHTCOOL);else if (IaOUZHPpEIjzyXTnaV == (162 + Math.round((Math.pow(Math.sin(" ascii
    $s4  = "function dxCjZdwCTUBUXMr(oPeEOfDpXoDxlLfiRTrKOfA,AdmgN){return oPeEOfDpXoDxlLfiRTrKOfA.charAt(AdmgN);}" fullword ascii
    $s5  = "function PievRqfkIzzYVYk(wwVeEvdcHkxeV,eaFoJsrOqkhQqhNVwZ){return wwVeEvdcHkxeV.indexOf(eaFoJsrOqkhQqhNVwZ);}" fullword ascii
    $s6  = "Z += RzHUeINj(eGwJjZRfkgGQnWeTeKHTCOOL, eYcBCVryv, IbngQVpuHy);} while (gVWTDtmSkVkiDF < fykHJbZRCMmYs.length);return YGCKODpLZ;" ascii
    $s7  = "function RzHUeINj(ZMIgulPNvm,BRDKKYcdfNGjuVQhavq,PajJrBNqpEHMLWoIzQoabw){return String.fromCharCode(ZMIgulPNvm,BRDKKYcdfNGjuVQha" ascii
    $s8  = "function RzHUeINj(ZMIgulPNvm,BRDKKYcdfNGjuVQhavq,PajJrBNqpEHMLWoIzQoabw){return String.fromCharCode(ZMIgulPNvm,BRDKKYcdfNGjuVQha" ascii
    $s9  = "function EYGHACKmRTCKNpb(XUiksOokbO,pickygMTEegLNRnaYooDivyX){return String.fromCharCode(XUiksOokbO,pickygMTEegLNRnaYooDivyX);}" fullword ascii
    $s10 = "function YH(RowusGtmiF){return String.fromCharCode(RowusGtmiF);}" fullword ascii
    $s11 = "function BxDPasZ(fykHJbZRCMmYs) {var HOqAvxoaHgzqcMmgrX = xwRcgSbv.join(SlFWcRIKde[0]);var eGwJjZRfkgGQnWeTeKHTCOOL, eYcBCVryv, " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}