rule sig_20160531_4827a9920ee2d84a747e7704e245408d {
  meta:
    description = "datamaliciousorder - file 20160531_4827a9920ee2d84a747e7704e245408d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49f53c365f74c16feb18d3f5e391af929cfeeab6dd3bab31110303174a440733"

  strings:
    $s1  = "var ulinlUSBlapwl=function(){return WScript.CreateObject(iGbuOtutLIGntjNNfkur[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function NLCBHAlGu(wGfwBtHVHygulveMO,PkrXcOJneMXwlMWt){return wGfwBtHVHygulveMO.charAt(PkrXcOJneMXwlMWt);}" fullword ascii
    $s3  = "function mGKThrJm(aIWcKSCOEBOYV) {var DvZURmKwKNXiiHWJrrMyFY = xTcCFiOgTVyGCqKoKQgV.join(iGbuOtutLIGntjNNfkur[7]);var eVKlekRKH," ascii
    $s4  = "function VBlYUTchUvRNNuV(YOYiGefxLL,wCYhhIyGktxLNc,ipmIz){return String.fromCharCode(YOYiGefxLL,wCYhhIyGktxLNc,ipmIz);}" fullword ascii
    $s5  = "(McrRXxNiOgEaiZ,0x1,0x0)}function KojmXoRVM(eCzvcs,XkGtpW,DuNIRvMLsb){var NKsAhvyOlT=eCzvcs.createtextfile(XkGtpW,true);NKsAhvyO" ascii
    $s6  = "(McrRXxNiOgEaiZ,0x1,0x0)}function KojmXoRVM(eCzvcs,XkGtpW,DuNIRvMLsb){var NKsAhvyOlT=eCzvcs.createtextfile(XkGtpW,true);NKsAhvyO" ascii
    $s7  = "KlekRKH, OEylwobWsPqLNI, NIzZLwTCuTQcgjWsG);} while (ozHVfsGOBVTa < aIWcKSCOEBOYV.length);return lwyQKRVmaGJdzBbKpA;}" fullword ascii
    $s8  = "YCgjVRBF == 64) lwyQKRVmaGJdzBbKpA += aHrfboiAWxXHrqMzA(eVKlekRKH, OEylwobWsPqLNI);else lwyQKRVmaGJdzBbKpA += VBlYUTchUvRNNuV(eV" ascii
    $s9  = ">> 8 & 0xff;NIzZLwTCuTQcgjWsG = vokCkbWWvs & 0xff;if (LQdoPALSARhD == 64) lwyQKRVmaGJdzBbKpA += jd(eVKlekRKH);else if (uqqhEbhSn" ascii
    $s10 = "function gfmUO(DPujwyUe,NGxlgfDUcpeM,ZMNAezaijFpa){bdynbfHJvAyBg=DPujwyUe.split(ZMNAezaijFpa);oTfEnVwVCY = iGbuOtutLIGntjNNfkur[" ascii
    $s11 = "function xIrfSMSAS(){return gfmUO(iGbuOtutLIGntjNNfkur[11],[2,4,8,10],iGbuOtutLIGntjNNfkur[12]);}" fullword ascii
    $s12 = "function ejztudnXlK(TpKfvyFoTfy,McrRXxNiOgEaiZ) {var PmwoLCNLTZlKM=[iGbuOtutLIGntjNNfkur[15]];TpKfvyFoTfy[PmwoLCNLTZlKM[0]]" fullword ascii
    $s13 = "var gfYwWMjSrtH=function(){return new ActiveXObject(iGbuOtutLIGntjNNfkur[1]);}();" fullword ascii
    $s14 = "function SJCdIixJRY(){return gfmUO(iGbuOtutLIGntjNNfkur[13],[0,3,6],iGbuOtutLIGntjNNfkur[14]);}" fullword ascii
    $s15 = "function rlhdSRVDYdeSElyJudLF(EZZActIJJaeiXKlyMZkUv,ejqkPGHU){return EZZActIJJaeiXKlyMZkUv.indexOf(ejqkPGHU);}" fullword ascii
    $s16 = "function mGKThrJm(aIWcKSCOEBOYV) {var DvZURmKwKNXiiHWJrrMyFY = xTcCFiOgTVyGCqKoKQgV.join(iGbuOtutLIGntjNNfkur[7]);var eVKlekRKH," ascii
    $s17 = "function jd(sQeKrBw){return String.fromCharCode(sQeKrBw);}" fullword ascii
    $s18 = "function kNADUpMpqGy(){return ulinlUSBlapwl.ExpandEnvironmentStrings(Vfoily())}" fullword ascii
    $s19 = "function aHrfboiAWxXHrqMzA(yZFtzxEXaVXUAwLZpuzWAyLS,qXDgaSPQvLoNsjcpIoUkSSq){return String.fromCharCode(yZFtzxEXaVXUAwLZpuzWAyLS" ascii
    $s20 = "function gfmUO(DPujwyUe,NGxlgfDUcpeM,ZMNAezaijFpa){bdynbfHJvAyBg=DPujwyUe.split(ZMNAezaijFpa);oTfEnVwVCY = iGbuOtutLIGntjNNfkur[" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}