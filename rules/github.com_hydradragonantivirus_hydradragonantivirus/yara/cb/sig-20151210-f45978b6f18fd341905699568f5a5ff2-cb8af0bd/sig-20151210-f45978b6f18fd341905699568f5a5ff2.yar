rule sig_20151210_f45978b6f18fd341905699568f5a5ff2 {
  meta:
    description = "datamaliciousorder - file 20151210_f45978b6f18fd341905699568f5a5ff2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25b71bc27188ec12160ea9e857c80a1f1801df814f80541a8264d25967364a54"

  strings:
    $s1  = "function DXgkPnl(HoqmoaPJcigoxuKYBhcUdwcmCSuVUFnZAqmm) {return !isNaN(parseFloat(HoqmoaPJcigoxuKYBhcUdwcmCSuVUFnZAqmm)) && isFin" ascii
    $s2  = "function DXgkPnl(HoqmoaPJcigoxuKYBhcUdwcmCSuVUFnZAqmm) {return !isNaN(parseFloat(HoqmoaPJcigoxuKYBhcUdwcmCSuVUFnZAqmm)) && isFin" ascii
    $s3  = "VvozUvT=(-802+802)/592;while(true){if(VvozUvT>=(74792+344)/587){break;}SNUFfOtbvjhFW[VvozUvT]=String.fromCharCode(VvozUvT);VvozU" ascii
    $s4  = "function HZxDJ(DKxGoADOnzE,VaWsKvLUAEWbc,YohTdkcM){THiE=parseInt(DKxGoADOnzE,VaWsKvLUAEWbc);xrzRd=THiE.toString(YohTdkcM);return" ascii
    $s5  = "function HZxDJ(DKxGoADOnzE,VaWsKvLUAEWbc,YohTdkcM){THiE=parseInt(DKxGoADOnzE,VaWsKvLUAEWbc);xrzRd=THiE.toString(YohTdkcM);return" ascii
    $s6  = "ZgeIeN[JbAbbwgAEMF]=(-658+658)/675; while(true) { if(LnxZgeIeN[JbAbbwgAEMF] > zsWrA[JbAbbwgAEMF].length-(-61+804)/743) { break; " ascii
    $s7  = " xrzRd;}function DgSEklXWhhOuCpi(BSgreupPrBkIOziPr){eval(BSgreupPrBkIOziPr)}" fullword ascii
    $s8  = "function ICUCXNHIoRbRxhBhT(zsWrA){AjCvXszhvXA= '';for(JbAbbwgAEMF=(-420+420)/380; JbAbbwgAEMF < (4+906)/455; JbAbbwgAEMF++) {Lnx" ascii
    $s9  = "function hqBFckDjIShgmgmKqchitKMUKLisuFJIUplmYwNAySTmWaAqWHQBfn(rOaKkLUHvdeit,aXJFSnviUJdKNm){ return SNUFfOtbvjhFW[HZxDJ(rOaKkL" ascii
    $s10 = "function rqWSvCSMmLZ(gMWQnfmY,BhiRwv){return gMWQnfmY.split(BhiRwv)}" fullword ascii
    $s11 = "} return AjCvXszhvXA}" fullword ascii
    $s12 = "VvozUvT=(-802+802)/592;while(true){if(VvozUvT>=(74792+344)/587){break;}SNUFfOtbvjhFW[VvozUvT]=String.fromCharCode(VvozUvT);VvozU" ascii
    $s13 = "function hqBFckDjIShgmgmKqchitKMUKLisuFJIUplmYwNAySTmWaAqWHQBfn(rOaKkLUHvdeit,aXJFSnviUJdKNm){ return SNUFfOtbvjhFW[HZxDJ(rOaKkL" ascii
    $s14 = "function ICUCXNHIoRbRxhBhT(zsWrA){AjCvXszhvXA= '';for(JbAbbwgAEMF=(-420+420)/380; JbAbbwgAEMF < (4+906)/455; JbAbbwgAEMF++) {Lnx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}