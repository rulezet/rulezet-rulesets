rule sig_20160527_a4d9ee3270e135b2dfbe02a7ef752142 {
  meta:
    description = "datamaliciousorder - file 20160527_a4d9ee3270e135b2dfbe02a7ef752142.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63146564405e079d7130380fe9cb4e1ee7fd29f8d5286f9c5505d74c613183d0"

  strings:
    $s1  = "function qHwkoVlRDapmB() {return WScript;}function DfWNclxl(){return iOYIOt.ExpandEnvironmentStrings(UbAaInzV())}" fullword ascii
    $s2  = "function MZaSdgClIyymnbs(RaBLKhPKIhO,YlozJOdbwNpuDeECuQkE){return RaBLKhPKIhO.charAt(YlozJOdbwNpuDeECuQkE);}" fullword ascii
    $s3  = "function NcQBgM(shRdAekapQqoT) {var fWvrvsXZDfAeJalgYAGlddNV = zlzGTMMrwTubaapdUhe.join(uMUup[6]);var TKGTY, JJuNETokxftGHMIWUUD" ascii
    $s4  = "GgLOeUZnEWqdyA & 0xff;if (tBKQBQudGCFnXb == 64) AGiaJLiLjAOdZKIsSlbbYE += kW(TKGTY);else if (miHYx == 64) AGiaJLiLjAOdZKIsSlbbYE" ascii
    $s5  = "function kW(ZbZwKMHw){return String.fromCharCode(ZbZwKMHw);}" fullword ascii
    $s6  = "var iOYIOt=function(){return qHwkoVlRDapmB().CreateObject(uMUup[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s7  = "var AYwMNJTArmRl = cEYvhNMqgCGNpd.createtextfile(iOYIOt.ExpandEnvironmentStrings(uMUup[2]+uMUup[3])+String.fromCharCode(92)+uMUu" ascii
    $s8  = "var cEYvhNMqgCGNpd=function(){return new ActiveXObject(uMUup[0]);}();" fullword ascii
    $s9  = "function NcQBgM(shRdAekapQqoT) {var fWvrvsXZDfAeJalgYAGlddNV = zlzGTMMrwTubaapdUhe.join(uMUup[6]);var TKGTY, JJuNETokxftGHMIWUUD" ascii
    $s10 = "function kBxSzcHEJMwS(){return EaOUkHuFhK(uMUup[12],[0,3,6],uMUup[13]);}" fullword ascii
    $s11 = "function aafXDHUSWXrp(){return EaOUkHuFhK(uMUup[10],[2,4,8,10],uMUup[11]);}" fullword ascii
    $s12 = "function pKPxaofDXHol(dpBymRwexlof,aZPObnvIOOrZsTpUgTquBi,hhRNrY){return String.fromCharCode(dpBymRwexlof,aZPObnvIOOrZsTpUgTquBi" ascii
    $s13 = "function pKPxaofDXHol(dpBymRwexlof,aZPObnvIOOrZsTpUgTquBi,hhRNrY){return String.fromCharCode(dpBymRwexlof,aZPObnvIOOrZsTpUgTquBi" ascii
    $s14 = " += sdNFaTNh(TKGTY, JJuNETokxftGHMIWUUDsJ);else AGiaJLiLjAOdZKIsSlbbYE += pKPxaofDXHol(TKGTY, JJuNETokxftGHMIWUUDsJ, aEIgO);} wh" ascii
    $s15 = "function sdNFaTNh(EQqAvONaOkfF,zpiXZPkKpJgCGLUdsmtqEx){return String.fromCharCode(EQqAvONaOkfF,zpiXZPkKpJgCGLUdsmtqEx);}" fullword ascii
    $s16 = "function QIOcfqKxIPesTUcVefd(KyWEvkUd,SsuzH){return KyWEvkUd.indexOf(SsuzH);}" fullword ascii
    $s17 = "ile (dDoMHfcyOLphKlS < shRdAekapQqoT.length);return AGiaJLiLjAOdZKIsSlbbYE;}" fullword ascii
    $s18 = "function UbAaInzV(){return EaOUkHuFhK(uMUup[8],[1,5,7],uMUup[9]);}" fullword ascii
    $s19 = "p[4],true);" fullword ascii
    $s20 = "GSvZSe<ZCAZSQfjMnXJc.length;DZGSvZSe++) {wefKjbjoTHtcL+=nyWkhowH[ZCAZSQfjMnXJc[DZGSvZSe]];}return wefKjbjoTHtcL.substring(3,wefK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}