rule sig_20151216_0e99f20a54d3d2a1afce1a667f9f0987 {
  meta:
    description = "datamaliciousorder - file 20151216_0e99f20a54d3d2a1afce1a667f9f0987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5548f78ac146848cafa63dc902259b71018b960a3d12c06fbe79fb543387b853"

  strings:
    $s1  = "Math.cos(595), 2) - 1)));} ClQgLtzfQ[NicfYvvhywm]++;}NicfYvvhywm++;} return RhurOmuicuw}" fullword ascii
    $s2  = "function JyugDBuymELDWmNzK(WMuFK){RhurOmuicuw= '';NicfYvvhywm=Math.round((Math.pow(Math.sin(592), 2) + Math.pow(Math.cos(592), 2" ascii
    $s3  = "th.pow(Math.cos(226), 2) - 1)); while(true) { if(ClQgLtzfQ[NicfYvvhywm] > WMuFK[NicfYvvhywm].length-(802+2)/804) { break; } if (" ascii
    $s4  = ") - 1));while(true){if (NicfYvvhywm >= (2399+277)/446){break;}ClQgLtzfQ[NicfYvvhywm]=Math.round((Math.pow(Math.sin(226), 2) + Ma" ascii
    $s5  = "function JyugDBuymELDWmNzK(WMuFK){RhurOmuicuw= '';NicfYvvhywm=Math.round((Math.pow(Math.sin(592), 2) + Math.pow(Math.cos(592), 2" ascii
    $s6  = "function TbYmhYy(svMsuyKLUzOsnCznVnemJXEmanpYijPpfSYK) {return !qCyjuMHdSFA(SZCeKqrZVTpkBJc(svMsuyKLUzOsnCznVnemJXEmanpYijPpfSYK" ascii
    $s7  = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s8  = "function d(WEOzAbQEyPxK,lQgRVkuymbbrJK){WEOzAbQEyPxK.push(lQgRVkuymbbrJK);}" fullword ascii
    $s9  = "function gxCmeZTNLBAg(pobcdsTKantuH) {return isFinite(pobcdsTKantuH);}" fullword ascii
    $s10 = "function jhvff(QkDWRgSaElM,kWUDElMWwsWcm,AvgYwCKl){VSUm=nYoeiPYBTjSMeutrV(QkDWRgSaElM,kWUDElMWwsWcm);VnrrB=VSUm.toString(AvgYwCK" ascii
    $s11 = "function SZCeKqrZVTpkBJc(TNApXhRlItalmdRykCW) {return parseFloat(TNApXhRlItalmdRykCW);}" fullword ascii
    $s12 = "function TbYmhYy(svMsuyKLUzOsnCznVnemJXEmanpYijPpfSYK) {return !qCyjuMHdSFA(SZCeKqrZVTpkBJc(svMsuyKLUzOsnCznVnemJXEmanpYijPpfSYK" ascii
    $s13 = "function M(MyKBhNBFGybLbT,OdKtmLHRADEYo,ogTqRdmoKrI) {MyKBhNBFGybLbT[OdKtmLHRADEYo]=ogTqRdmoKrI;}" fullword ascii
    $s14 = "function qCyjuMHdSFA(sRDEkxbLoexJFn) {return isNaN(sRDEkxbLoexJFn);}" fullword ascii
    $s15 = "function OaiDsaeyFWWnhZK(WkKzfAnVxfTFRzShM,NhLomRINILKQBEzqhPQMURGEUkMGSorhPD,psDTyiFJtRMVBYAhmiNmhnqcIvlWBmstZYV){eval(WkKzfAnV" ascii
    $s16 = "function OaiDsaeyFWWnhZK(WkKzfAnVxfTFRzShM,NhLomRINILKQBEzqhPQMURGEUkMGSorhPD,psDTyiFJtRMVBYAhmiNmhnqcIvlWBmstZYV){eval(WkKzfAnV" ascii
    $s17 = "function DaDKZfRZGKvooSPlAzYEYjQEmYGAjyqHsZtMrKlPmZzuAgVDxcbpJT(mpSKQxknKwTaS,leuGIIsjjlSDqm){ return sXPXide[qcInHDOc[jhvff(mpS" ascii
    $s18 = "function DaDKZfRZGKvooSPlAzYEYjQEmYGAjyqHsZtMrKlPmZzuAgVDxcbpJT(mpSKQxknKwTaS,leuGIIsjjlSDqm){ return sXPXide[qcInHDOc[jhvff(mpS" ascii
    $s19 = "function jhvff(QkDWRgSaElM,kWUDElMWwsWcm,AvgYwCKl){VSUm=nYoeiPYBTjSMeutrV(QkDWRgSaElM,kWUDElMWwsWcm);VnrrB=VSUm.toString(AvgYwCK" ascii
    $s20 = "function nYoeiPYBTjSMeutrV(tdHVLAJHfD,cfOHWPjOvs) {return parseInt(tdHVLAJHfD,cfOHWPjOvs);}" fullword ascii

  condition:
    uint16(0) == 0x6371 and
    8 of them
}