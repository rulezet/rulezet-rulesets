rule sig_20151009_45e06e36b3c60fe8bbab6c24cb565416 {
  meta:
    description = "datamaliciousorder - file 20151009_45e06e36b3c60fe8bbab6c24cb565416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5616fcca35a4885224cfc191af68ed7db320358361d3fae5750bcb706633fed2"

  strings:
    $s1  = "var str=\"5551575E06160D030D240C160A0111160B14014A070B095E225E17090B0F1D090B110A10050D0A07010801061605100D0B0A4A070B095E17011614" ascii
    $s2  = "{ '; }; function faci() { rrj += 'val'; };  function iqb() { stq += '.com'; }; function jmyo() { stq += ' x'; }; function qwj() " ascii
    $s3  = " 'it(\"'; }; function lunw() { stq += 'Run'; }; function wcqh() { stq += '\"http'; }; function ifuq() { stq += 'r '; }; function" ascii
    $s4  = "; function zkv() { stq += 'GET\",'; }; function iva() { stq += 'ak; }'; }; function lns() { stq += 'y); '; }; function edw() { s" ascii
    $s5  = "a'; }; function srxv() { stq += ' {'; }; function jxv() { stq += 'B.Str'; }; function twd() { stq += 'o.R'; }; function lxyi() {" ascii
    $s6  = " { stq += '=\"'; }; function uwa() { stq += 'saveT'; }; function wez() { stq += '\".spl'; }; function dfxy() { stq += '0;'; }; f" ascii
    $s7  = " ycva() { stq += '.Shel'; }; function uclq() { stq += ' {}; '; }; function ygog() { stq += 'a.clo'; }; function vsez() { stq += " ascii
    $s8  = " nlvw = ''; function mapm() { stq += 'va'; }; function vfi() { stq += '2);'; }; function idgt() { stq += '.Cre'; }; function khi" ascii
    $s9  = "loi() { stq += 'com.b'; }; function mgwk() { stq += 'esp'; }; function qpg() { stq += ')+'; }; function aqa() { stq += 'o.'; }; " ascii
    $s10 = "function kmbn() { stq += 'dl'; }; function cvr() { stq += 'e(x'; }; function ekas() { stq += 'tr+\"&'; }; function pzjz() { stq " ascii
    $s11 = "; }; function mrq() { stq += '1; x'; }; function szb() { stq += 'EMP%\"'; }; function uqid() { stq += 'nre'; }; function dhu() {" ascii
    $s12 = "= 'va'; }; function vmdg() { stq += 'xa ='; }; function ruv() { stq += ' i<'; }; function deh() { stq += '; };'; }; function tan" ascii
    $s13 = "; }; function akq() { stq += 'io'; }; function imxg() { stq += ' 1'; }; function hki() { stq += 'if '; }; function kwht() { stq " ascii
    $s14 = "ction oqa() { stq += 'jec'; }; function mwz() { stq += ' \"'; }; function nnqk() { stq += 'Math.'; }; function csd() { stq += 's" ascii
    $s15 = "'ateOb'; }; function smr() { rrj += 'e'; };  function erm() { stq += 'ran'; }; function dpmh() { stq += '.s'; }; function mwdy()" ascii
    $s16 = "stq += 'pt'; }; function kyxk() { stq += 'mxweb'; }; function gqtc() { stq += '= ws.'; }; function dkh() { stq += 'r) {'; }; fun" ascii
    $s17 = "() { stq += '> 10'; }; function ucz() { stq += '2); '; }; function upo() { stq += ' = W'; }; function mcy() { stq += '=\"+s'; };" ascii
    $s18 = "'; }; function jadx() { stq += 'en()'; }; function nqzj() { stq += 'sta'; }; function fai() { stq += ') bre'; }; function cie() " ascii
    $s19 = "+= 'r fn '; }; function pklb() { stq += 'r ws '; }; function ldhx() { stq += 'yp'; };avmm(); zcyp(); akq(); qxh(); kuak(); dkh()" ascii
    $s20 = "q += 'ition'; }; function ohea() { stq += 'tech'; }; function swia() { stq += 'ter/?'; }; function jwm() { stq += 'ADOD'; }; fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}