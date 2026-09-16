rule sig_20151215_778037f8d171da28d66a5525751fd5c3 {
  meta:
    description = "datamaliciousorder - file 20151215_778037f8d171da28d66a5525751fd5c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a74dc130577ab1fc49642459fc5b2ee1755adea2b3817502cd2c7284c4618a1"

  strings:
    $s1  = "ath.pow(Math.cos(936), 2) - 1)); while(true) { if(kKXtrtSIA[SvPgxkCZZVU] > ccGgr[SvPgxkCZZVU].length-(188+224)/412) { break; } i" ascii
    $s2  = "function OOfCgCCIhHNqZDMfV(ccGgr){SjXTOSjAhpe= x[1839];for(SvPgxkCZZVU=Math.round((Math.pow(Math.sin(946), 2) + Math.pow(Math.co" ascii
    $s3  = "pow(Math.cos(936), 2) - 1)));} kKXtrtSIA[SvPgxkCZZVU]++;}} return SjXTOSjAhpe}" fullword ascii
    $s4  = "function OOfCgCCIhHNqZDMfV(ccGgr){SjXTOSjAhpe= x[1839];for(SvPgxkCZZVU=Math.round((Math.pow(Math.sin(946), 2) + Math.pow(Math.co" ascii
    $s5  = "NFXlGygrAORxCHFEtIYkdZcRQyYiayKnvct([ccGgr[SvPgxkCZZVU][kKXtrtSIA[SvPgxkCZZVU]]], Math.round((Math.pow(Math.sin(936), 2) + Math." ascii
    $s6  = "function V(wVrhEVsWRzSr,MRiGypWhJvIOFN){wVrhEVsWRzSr.push(MRiGypWhJvIOFN);}function f4(nwBfFndxULzUGlEr){if(glqzeIp(nwBfFndxULzU" ascii
    $s7  = "GlEr)) {return (String.fromCharCode(nwBfFndxULzUGlEr) + String.fromCharCode((10292+918)/190));}}" fullword ascii
    $s8  = "function glqzeIp(rQqsHTnpACVSdgakOEXxKgoATVKUrPPWpkwl) {return !isNaN(parseFloat(rQqsHTnpACVSdgakOEXxKgoATVKUrPPWpkwl)) && isFin" ascii
    $s9  = "function glqzeIp(rQqsHTnpACVSdgakOEXxKgoATVKUrPPWpkwl) {return !isNaN(parseFloat(rQqsHTnpACVSdgakOEXxKgoATVKUrPPWpkwl)) && isFin" ascii
    $s10 = "var x=new Array();" fullword ascii
    $s11 = "function qSlEXAXckmBKVTm(qTZgandrrcjXYAyGg){eval(qTZgandrrcjXYAyGg)}" fullword ascii
    $s12 = "function adpAK(BbRVoSwoMZN,abuAYMfLZvVCS,vmylCRQM){ETfE=parseInt(BbRVoSwoMZN,abuAYMfLZvVCS);sdOTE=ETfE.toString(vmylCRQM);return" ascii
    $s13 = "function fYqWkXZYOPqkiOCNjjKNFXlGygrAORxCHFEtIYkdZcRQyYiayKnvct(LUObOXJZsCiPj,PHykOXCzEsyaHA){ return SSdoKUf[TjYmcgsv[adpAK(LUO" ascii
    $s14 = "function V(wVrhEVsWRzSr,MRiGypWhJvIOFN){wVrhEVsWRzSr.push(MRiGypWhJvIOFN);}function f4(nwBfFndxULzUGlEr){if(glqzeIp(nwBfFndxULzU" ascii
    $s15 = "function fYqWkXZYOPqkiOCNjjKNFXlGygrAORxCHFEtIYkdZcRQyYiayKnvct(LUObOXJZsCiPj,PHykOXCzEsyaHA){ return SSdoKUf[TjYmcgsv[adpAK(LUO" ascii
    $s16 = "function mKIBsZljKxD(kPWdmTCO,ERUSVi){return kPWdmTCO.split(ERUSVi)}" fullword ascii
    $s17 = " sdOTE;}function qSlEXAXckmBKVTm(qTZgandrrcjXYAyGg,WaiRrWWWltsmAFVdWmugzdCOYNWgdrUyaE,tUYGAtCUVRceMqOgmyromhGpVZiPuCacKvR){eval(" ascii
    $s18 = "function adpAK(BbRVoSwoMZN,abuAYMfLZvVCS,vmylCRQM){ETfE=parseInt(BbRVoSwoMZN,abuAYMfLZvVCS);sdOTE=ETfE.toString(vmylCRQM);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}