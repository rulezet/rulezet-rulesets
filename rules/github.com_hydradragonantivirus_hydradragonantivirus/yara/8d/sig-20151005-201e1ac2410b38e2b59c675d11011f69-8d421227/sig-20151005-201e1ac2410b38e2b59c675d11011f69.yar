rule sig_20151005_201e1ac2410b38e2b59c675d11011f69 {
  meta:
    description = "datamaliciousorder - file 20151005_201e1ac2410b38e2b59c675d11011f69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef05d952f829c2d150103d62f25b61bfe055295880899a2fb3c7b2d747067982"

  strings:
    $s1  = "var str=\"5551555E060B0300050A240C160A0111160B14014A070B095E225E0716111E0608050A07050D0A1001160A05070D0B0A05084A070B095E17011614" ascii
    $s2  = " }; function nxs() { yieu += '(\"GET'; }; function wio() { yieu += 'nctio'; }; function mxwh() { yieu += ' 0'; }; function xnmh(" ascii
    $s3  = "65E5550505054575C5D57565E55\"; function toys() { yieu += '0000'; }; function fuxc() { yieu += '.php'; }; function xda() { yieu +" ascii
    $s4  = "+= '\"%TEM'; }; function zjxt() { yieu += '; xa.'; }; function opmk() { yieu += '= fu'; }; function ldt() { yieu += '.fro'; }; f" ascii
    $s5  = "lzsa() { yieu += 'a.siz'; }; function nylv() { yieu += ' dl'; }; function ltmu() { yieu += 'nre'; }; function brmt() { yieu += '" ascii
    $s6  = "{ yieu += '; } c'; }; function iwiv() { yieu += ' { ws'; }; function bnaa() { yieu += 'com\"'; }; function fshz() { yieu += 'clo" ascii
    $s7  = "function aqrt() { yieu += 'e);'; }; var yieu = ''; function rxl() { yieu += '; } '; }; function zcon() { yieu += ' tr'; }; funct" ascii
    $s8  = "+= '.S'; }; function hcmo() { yieu += ' v'; }; function zupo() { yieu += ' f'; }; function elu() { yieu += 'l(33'; }; function o" ascii
    $s9  = "yieu += 'dy); '; }; function ihhh() { yieu += ' {'; }; function cxxc() { yieu += ' = ne'; }; function dwhc() { yieu += '.save'; " ascii
    $s10 = "o.'; }; function hpar() { yieu += 'WScr'; }; function xrte() { yieu += 'ro'; }; function dhiy() { yieu += 'atch'; }; function gt" ascii
    $s11 = " function vbs() { yieu += '00)'; }; function mzb() { yieu += 'nd()'; }; function afwu() { yieu += ' n'; }; function luu() { yieu" ascii
    $s12 = "() { yieu += '; '; }; function xlt() { yieu += ' 1'; }; function hstq() { yieu += ' i++'; }; function ethl() { yieu += ' x'; }; " ascii
    $s13 = "tv() { yieu += 'exe\"'; }; function kppr() { yieu += 't('; }; function rht() { yieu += 'xo.R'; }; function uqfh() { yieu += 'f '" ascii
    $s14 = "; function tyhp() { yieu += 'e('; }; function bcim() { yieu += 'larb'; }; function cpoa() { yieu += 'dn ='; }; function lfq() { " ascii
    $s15 = " 'tio'; }; function kwbu() { yieu += 'si'; }; function rflp() { yieu += ' xo.'; }; function vys() { yieu += '\")'; }; function x" ascii
    $s16 = "= 'd(M'; }; function nvbi() { yieu += '.c'; }; function absl() { yieu += 'onar'; }; function xyx() { yieu += '}; };'; }; functio" ascii
    $s17 = "ion tnv() { yieu += ' ('; }; function dut() { yieu += '<b.l'; }; function rzui() { yieu += 'L2.X'; }; function mfpe() { yieu += " ascii
    $s18 = "nction tuq() { yieu += 'te ='; }; function kbnk() { yieu += 's.E'; }; function bdb() { yieu += ' xa.'; }; function qum() { yieu " ascii
    $s19 = "'ings('; }; function fea() { yieu += 'seBo'; }; function uqok() { yieu += 'stat'; }; function rfep() { yieu += 'tring'; }; funct" ascii
    $s20 = " function qdyf() { yieu += ' xo'; }; function ppu() { yieu += 'm('; }; function emlq() { yieu += '; '; }; function bgn() { yieu " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}