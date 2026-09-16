rule sig_20151023_92dd67d79ba4ca7fc1811cf13aeba4c3 {
  meta:
    description = "datamaliciousorder - file 20151023_92dd67d79ba4ca7fc1811cf13aeba4c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6037dfcfbb6fd01952da77537c76bd5bc36a6383451875fb9e345f99313d791"

  strings:
    $s1  = "var str=\"55515C5E160D1005240C160A0111160B14014A070B095E275E0F010A10070D101D020B16001605100D0A03174A070B095E17555E55505051515C51" ascii
    $s2  = "n crl() { etvc += ');'; }; function qqby() { etvc += '.com'; }; function cyjw() { etvc += 'lit('; }; function qnki() { etvc += '" ascii
    $s3  = "r'; }; function isna() { etvc += 'ope'; }; function vyqr() { etvc += 'LHTTP'; }; function hmj() { etvc += 'xo.re'; }; function o" ascii
    $s4  = "psc() { etvc += 'a.ope'; }; function hvlr() { etvc += '; '; }; function hprw() { etvc += '+\".e'; }; function gmz() { etvc += '+" ascii
    $s5  = "= ' 2'; }; function qzfz() { etvc += ') '; }; function rzri() { etvc += 'fo'; }; var rger = ''; function bev() { etvc += '.Cre';" ascii
    $s6  = ") { etvc += 'a = '; }; function hdg() { etvc += 'brea'; }; function afyb() { etvc += 'com n'; }; function hdu() { etvc += 'me'; " ascii
    $s7  = "o() { etvc += ' n++'; }; function mhpx() { etvc += 't.Cr'; }; function tbof() { etvc += '\"we'; }; function rar() { etvc += 'com" ascii
    $s8  = "jsz() { etvc += 'n();'; }; function exva() { etvc += 'ry { '; }; function fpn() { etvc += 'eObje'; }; function tev() { etvc += '" ascii
    $s9  = " function mojp() { etvc += 'tio'; }; function cod() { etvc += 'ar xo'; }; function usik() { etvc += 'MSXML'; }; function qfyq() " ascii
    $s10 = "ct('; }; function kdbw() { etvc += 'n+'; }; function zikg() { etvc += 'rior.'; }; function jtw() { etvc += '; }; '; }; function " ascii
    $s11 = "= 'n '; }; function nkp() { etvc += ' { dn'; }; function wfti() { etvc += 'e()'; }; function zez() { etvc += 'a.wr'; }; function" ascii
    $s12 = "etvc += ' }'; }; function oqiz() { etvc += 'eObje'; }; function mef() { etvc += 'Scr'; }; function isa() { etvc += ' xa.t'; }; f" ascii
    $s13 = "n vug() { etvc += '\"WScr'; }; function msfn() { etvc += ' ='; }; function ygg() { etvc += 'er/?'; }; var qwrb = ''; function ll" ascii
    $s14 = "unction vqm() { etvc += 'ar '; }; function ghk() { etvc += 'Code('; }; function vkzi() { etvc += ' {'; }; function fptf() { etvc" ascii
    $s15 = "= 'xo.st'; }; function eemd() { etvc += 'b = '; }; function ytz() { etvc += 'el'; }; function acvr() { etvc += '.Ex'; }; functio" ascii
    $s16 = " };  function tns() { etvc += 'ipt'; }; function aga() { etvc += 'pa'; }; function tvc() { etvc += 'tt'; }; function kxbv() { et" ascii
    $s17 = "456545E55\"; function kuy() { etvc += 'nseBo'; }; function ifv() { etvc += 'l\")'; }; function vpd() { etvc += 'tring'; }; funct" ascii
    $s18 = "etvc += 'TE'; }; function wrj() { etvc += 'd('; }; function gbtq() { etvc += 'als'; }; function jwl() { etvc += 'ntS'; }; functi" ascii
    $s19 = " += 'xo.s'; }; function vmf() { etvc += 's(\"%'; }; function sxs() { etvc += 'eat'; }; function ydjg() { etvc += 'Ru'; }; functi" ascii
    $s20 = "m() { etvc += ' x'; }; function qyg() { etvc += '); '; }; function nxo() { etvc += '\"+'; }; function gkx() { etvc += 'tch ('; }" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}