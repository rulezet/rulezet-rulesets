rule sig_20151217_1874dd4cab295ec7f1b09946a6726262 {
  meta:
    description = "datamaliciousorder - file 20151217_1874dd4cab295ec7f1b09946a6726262.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e0214def02b27e4a76d7421449042e43d348e16ba7f454f8d19240146e4ce8c"

  strings:
    $s1  = "function fnMypfNyMnCyGbYMk(TIsOO){OugtsFgVxFP= '';KghJKVsZnvv=Math.round((Math.pow(Math.sin(271), 2) + Math.pow(Math.cos(271), 2" ascii
    $s2  = "pow(Math.cos(516), 2) - 1)));} DYTARMtKl[KghJKVsZnvv]++;}KghJKVsZnvv++;} return OugtsFgVxFP}" fullword ascii
    $s3  = "th.pow(Math.cos(311), 2) - 1)); while(true) { if(DYTARMtKl[KghJKVsZnvv] > TIsOO[KghJKVsZnvv].length-(-214+789)/575) { break; } i" ascii
    $s4  = ") - 1));while(true){if (KghJKVsZnvv >= (3238+182)/570){break;}DYTARMtKl[KghJKVsZnvv]=Math.round((Math.pow(Math.sin(311), 2) + Ma" ascii
    $s5  = "rywSDIVzUbbEghTNpyBgEzfbEZuFxhuxvHz([TIsOO[KghJKVsZnvv][DYTARMtKl[KghJKVsZnvv]]], Math.round((Math.pow(Math.sin(516), 2) + Math." ascii
    $s6  = "function fnMypfNyMnCyGbYMk(TIsOO){OugtsFgVxFP= '';KghJKVsZnvv=Math.round((Math.pow(Math.sin(271), 2) + Math.pow(Math.cos(271), 2" ascii
    $s7  = "function ZQIHgkF(VcqaYkuefPFubNTfRGiTBHueeFfTDgVqaOcR) {return !FNdcjoiVjuM(aHTeOgQqAiUGIly(VcqaYkuefPFubNTfRGiTBHueeFfTDgVqaOcR" ascii
    $s8  = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s9  = "function aHTeOgQqAiUGIly(iZbsAyueGpPZAuLAuQH) {return parseFloat(iZbsAyueGpPZAuLAuQH);}" fullword ascii
    $s10 = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s11 = "p);return wanxS;}" fullword ascii
    $s12 = "function MOyUBzzLtNQpfvG(bkCJlAICUUfhVmzVX,RISXSKrGykKMGfXINDcfgCOOUpIYWPkUpA,jqvmMXUABLjREKltOfYObnlSStQYUgexCbc){eval(bkCJlAIC" ascii
    $s13 = "function FNdcjoiVjuM(DRZRnqHRGfqCCy) {return isNaN(DRZRnqHRGfqCCy);}" fullword ascii
    $s14 = "function mgnep(lwOrXgJFyWA,copBRLhKxnhCq,OVAInmOp){iHXe=HRvOwQhtvIDqJCCJs(lwOrXgJFyWA,copBRLhKxnhCq);wanxS=iHXe.toString(OVAInmO" ascii
    $s15 = "function mgnep(lwOrXgJFyWA,copBRLhKxnhCq,OVAInmOp){iHXe=HRvOwQhtvIDqJCCJs(lwOrXgJFyWA,copBRLhKxnhCq);wanxS=iHXe.toString(OVAInmO" ascii
    $s16 = "function W(ngWKpHvHNaWr,vsRvFyuMVMYbHJ){ngWKpHvHNaWr.push(vsRvFyuMVMYbHJ);}" fullword ascii
    $s17 = "function ZQIHgkF(VcqaYkuefPFubNTfRGiTBHueeFfTDgVqaOcR) {return !FNdcjoiVjuM(aHTeOgQqAiUGIly(VcqaYkuefPFubNTfRGiTBHueeFfTDgVqaOcR" ascii
    $s18 = "function SNLGeDiQwrnQ(lUoFXAdugVrxd) {return isFinite(lUoFXAdugVrxd);}" fullword ascii
    $s19 = "function n(hyfCbGDqUoanFh,bdwnwlnruYaAo,ZPZRhoZIaXQ) {hyfCbGDqUoanFh[bdwnwlnruYaAo]=ZPZRhoZIaXQ;}" fullword ascii
    $s20 = "function MOyUBzzLtNQpfvG(bkCJlAICUUfhVmzVX,RISXSKrGykKMGfXINDcfgCOOUpIYWPkUpA,jqvmMXUABLjREKltOfYObnlSStQYUgexCbc){eval(bkCJlAIC" ascii

  condition:
    uint16(0) == 0x7641 and
    8 of them
}