rule sig_20160527_e862fd8fbd22a2d79ca92674c9a07faa {
  meta:
    description = "datamaliciousorder - file 20160527_e862fd8fbd22a2d79ca92674c9a07faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c9ef8d9a4e54c42706c426531a6e0920f3bbd4419d438313e540750526affb4"

  strings:
    $s1  = "function yBfHEiFegxeRzd() {return WScript;}function efwVVgqfJlur(){return oCTWJpxHPi.ExpandEnvironmentStrings(GtkdPVkQVkFeb())}" fullword ascii
    $s2  = "function uJuKZxWCFLA(RxkuwLPMUkukIUyyUxMK,WpUhTnqwxOXMmZbgzKDm){return RxkuwLPMUkukIUyyUxMK.charAt(WpUhTnqwxOXMmZbgzKDm);}" fullword ascii
    $s3  = "C[14];for(PmszgTB=0;PmszgTB<LlwMCkupC.length;PmszgTB++) {OUSuO+=ggKtiSCj[LlwMCkupC[PmszgTB]];}return OUSuO.substring(3,OUSuO.len" ascii
    $s4  = "function KKZvPWI(){return LfLaXtbakOly(UUQWvpfpfOekpzyIVC[10],[2,4,8,10],UUQWvpfpfOekpzyIVC[11]);}" fullword ascii
    $s5  = "function GtkdPVkQVkFeb(){return LfLaXtbakOly(UUQWvpfpfOekpzyIVC[8],[1,5,7],UUQWvpfpfOekpzyIVC[9]);}" fullword ascii
    $s6  = "0xff;DGoyDNezBxtrYiUE = xvFlclckywsqAVacwrZB & 0xff;if (dhUjhVCOUMO == 64) tKtOv += Xt(SfInTYkrV);else if (GPork == 64) tKtOv +=" ascii
    $s7  = "function pIZIqocxVVHU(jIWhdSBaijKFo,TSqmVuiEmZyIQ) {var xueiQTktZ=[UUQWvpfpfOekpzyIVC[15]];jIWhdSBaijKFo[xueiQTktZ[0]](TSqmVuiEm" ascii
    $s8  = "function strEVX(qsYZgHgTDFrD,BHIoeuklQhaDRbRZKqovmBG){return qsYZgHgTDFrD.indexOf(BHIoeuklQhaDRbRZKqovmBG);}" fullword ascii
    $s9  = "function SBVMticMGHzxOPze(lSUNuRyVP,KLAZKWsaxcjizSyNZiS,gnWBYaDmXTazETmIKnS){return String.fromCharCode(lSUNuRyVP,KLAZKWsaxcjizS" ascii
    $s10 = "function HtygNKZLVXm(){return LfLaXtbakOly(UUQWvpfpfOekpzyIVC[12],[0,3,6],UUQWvpfpfOekpzyIVC[13]);}" fullword ascii
    $s11 = "var TzVtCiUmRCS = cmFYLSm.createtextfile(oCTWJpxHPi.ExpandEnvironmentStrings(UUQWvpfpfOekpzyIVC[2]+UUQWvpfpfOekpzyIVC[3])+String" ascii
    $s12 = "function Xt(LiUxQqifjBLLOLk){return String.fromCharCode(LiUxQqifjBLLOLk);}" fullword ascii
    $s13 = "function pIZIqocxVVHU(jIWhdSBaijKFo,TSqmVuiEmZyIQ) {var xueiQTktZ=[UUQWvpfpfOekpzyIVC[15]];jIWhdSBaijKFo[xueiQTktZ[0]](TSqmVuiEm" ascii
    $s14 = "function LfLaXtbakOly(iQGwjtpXbMoaYa,LlwMCkupC,IhwKBigsMmf){ggKtiSCj=iQGwjtpXbMoaYa.split(IhwKBigsMmf);OUSuO = UUQWvpfpfOekpzyIV" ascii
    $s15 = "function SBVMticMGHzxOPze(lSUNuRyVP,KLAZKWsaxcjizSyNZiS,gnWBYaDmXTazETmIKnS){return String.fromCharCode(lSUNuRyVP,KLAZKWsaxcjizS" ascii
    $s16 = ".fromCharCode(92)+UUQWvpfpfOekpzyIVC[4],true);" fullword ascii
    $s17 = "var oCTWJpxHPi=function(){return yBfHEiFegxeRzd().CreateObject(UUQWvpfpfOekpzyIVC[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s18 = "var cmFYLSm=function(){return new ActiveXObject(UUQWvpfpfOekpzyIVC[0]);}();" fullword ascii
    $s19 = "function fTYGjd(mZomugjjBAfse) {var GCZiyDZJsWcXkvLGECK = vmJXSzPbeLM.join(UUQWvpfpfOekpzyIVC[6]);var SfInTYkrV, BavachBXnqImNiI" ascii
    $s20 = "function LfLaXtbakOly(iQGwjtpXbMoaYa,LlwMCkupC,IhwKBigsMmf){ggKtiSCj=iQGwjtpXbMoaYa.split(IhwKBigsMmf);OUSuO = UUQWvpfpfOekpzyIV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}