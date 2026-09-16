rule sig_20151007_9bc612ca3a5039357665b36dc1c843e3 {
  meta:
    description = "datamaliciousorder - file 20151007_9bc612ca3a5039357665b36dc1c843e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba82c852ba42cc127c45b18eb501c7f1cdb81e1800d13b88f3d5a11cc879225e"

  strings:
    $s1  = "var str=\"5551565E0B14011605100D0B0A17240C160A0111160B14014A070B095E225E140B0805160D170517174A000B090D0A0D0B100109140B1605160D0B" ascii
    $s2  = " nncl += 'rnd'; }; function tpu() { nncl += 'b = '; }; function glkl() { nncl += '.com'; }; function bcp() { nncl += 'e ='; }; f" ascii
    $s3  = "ncl += '.exe'; }; function bbfs() { nncl += 'xa'; }; function fezo() { nncl += 'ry {'; }; function zml() { nncl += ' 1; x'; }; f" ascii
    $s4  = "ion kub() { nncl += 'r f'; }; function udbn() { nncl += '\"GET\"'; }; function tlcn() { nncl += ' W'; }; function rqmm() { nncl " ascii
    $s5  = "ion wvd() { nncl += '; va'; }; function hxl() { nncl += '.op'; }; function kbdh() { nncl += '.typ'; }; function norl() { nncl +=" ascii
    $s6  = "cl += '.ope'; }; function xhfv() { nncl += ')+\"'; }; function wptu() { nncl += 'tate '; }; function sgb() { nncl += 'e('; }; fu" ascii
    $s7  = "tion yrdr() { nncl += 'var i'; }; function xxb() { nncl += 't.She'; }; function whbm() { nncl += 'r d'; }; function zxk() { nncl" ascii
    $s8  = "n kfu() { nncl += 'l.ne'; }; function zatu() { nncl += 'Scr'; }; function mlt() { nncl += '\";'; }; function yhm() { nncl += 'am" ascii
    $s9  = "nncl += '.br '; }; function dsn() { nncl += ',2); '; }; function nuzq() { nncl += ') {'; }; function rdee() { nncl += '\"M'; }; " ascii
    $s10 = " function jreg() { nncl += 'hp?'; }; function ysws() { nncl += '.XM'; }; function aylh() { nncl += '; }'; }; function koxo() { n" ascii
    $s11 = "n qrs() { nncl += 'tate'; }; function rzym() { nncl += 'stat'; }; function xxki() { nncl += '; '; }; function iscv() { nncl += '" ascii
    $s12 = "n ypud() { nncl += 'oy.co'; }; function kjss() { nncl += '{}; }'; }; function rfgp() { nncl += 'pil'; }; function pgw() { nncl +" ascii
    $s13 = "= 'pt.C'; }; function thml() { nncl += '(xa.'; }; function hlzl() { nncl += '()'; }; function lnq() { nncl += 'l(fr'; }; functio" ascii
    $s14 = "'2)'; }; function mqik() { nncl += 't(\"'; }; function mbdz() { nncl += 'rip'; }; function bfan() { nncl += ' == 1'; }; function" ascii
    $s15 = "on ogb() { nncl += '; xa.'; }; function nmnf() { nncl += ' (xo.'; }; function edda() { nncl += 'on d'; }; function ziql() { nncl" ascii
    $s16 = " }; function ouk() { nncl += '== 4 '; };jjg(); ziql(); edda(); lnq(); nuzq(); kxp(); koxo(); tpu(); vqm(); njuw(); zxk(); glkl()" ascii
    $s17 = " nncl += 'ea'; }; function mrly() { nncl += '0)'; }; function imrn() { nncl += 'it'; }; function mng() { nncl += 'h.ro'; }; func" ascii
    $s18 = " ilx() { nncl += 'tch ('; }; function vuls() { nncl += 'Fu'; }; var wugs = ''; function yzuq() { nncl += '+b['; }; function ffq(" ascii
    $s19 = "unction dla() { nncl += ' va'; }; function aqfj() { nncl += '1,'; }; function cto() { nncl += ' if'; }; function dfu() { nncl +=" ascii
    $s20 = " { nncl += 'at'; }; function ekee() { nncl += 're'; }; function nhnv() { nncl += 'if'; }; function hbwi() { nncl += '&&'; }; fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}