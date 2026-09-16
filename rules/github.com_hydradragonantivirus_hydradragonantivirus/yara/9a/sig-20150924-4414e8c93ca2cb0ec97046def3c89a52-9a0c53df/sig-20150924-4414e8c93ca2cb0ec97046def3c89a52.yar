rule sig_20150924_4414e8c93ca2cb0ec97046def3c89a52 {
  meta:
    description = "datamaliciousorder - file 20150924_4414e8c93ca2cb0ec97046def3c89a52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47e040155cce7ff82a596f56c776dca606a5c2741af52ead743d859d9a6d9f75"

  strings:
    $s1  = "var str=\"5550525E0D0A020B24011C1405101001070C4A070B09\";function vudt() { daxgljy += 'ad'; }; function rmie() { daxgljy += 'bje" ascii
    $s2  = "() { daxgljy += '.com '; }; function nqtnxow() { daxgljy += 'SX'; }; function mxvdmsx() { daxgljy += '+St'; }; function tulej() " ascii
    $s3  = "+= '0; '; }; function loiu() { daxgljy += '; xo'; }; function fugzsae() { daxgljy += 'TEMP'; }; function qhdxphk() { daxgljy += " ascii
    $s4  = "'2); t'; }; function plog() { daxgljy += ' { '; }; function kmkcm() { daxgljy += 'ws.'; }; function zllf() { daxgljy += 'fr+\"';" ascii
    $s5  = "; }; function cxpxm() { daxgljy += '.clo'; }; function cptyj() { daxgljy += 'om('; }; function jfuhl() { daxgljy += '= '; }; fun" ascii
    $s6  = "'; }; function dquvy() { daxgljy += 'Run(f'; }; function sdcwboz() { daxgljy += 'ry { '; }; function ifaw() { daxgljy += 'rand';" ascii
    $s7  = " daxgljy += 'hav'; }; function hsuhc() { daxgljy += ' && x'; }; function ypeymas() { daxgljy += ' 1; '; }; function weotbb() { d" ascii
    $s8  = "lvxw() { daxgljy += '.onr'; }; function pqsympx() { daxgljy += '559'; }; function bsvgugx() { daxgljy += '&id'; }; function sbxp" ascii
    $s9  = "}; function ntevxdv() { daxgljy += '=\"+s'; }; function rpvq() { daxgljy += '\"http'; }; function iwowb() { daxgljy += 'ype'; };" ascii
    $s10 = "qk() { daxgljy += '= f'; }; function jjik() { daxgljy += 'a.siz'; }; function wgkce() { daxgljy += '(dn ='; }; function hwfwsmc(" ascii
    $s11 = "x() { daxgljy += '.wri'; }; function ovlh() { daxgljy += 'xa.sa'; }; function vsvn() { daxgljy += 'o.o'; }; function bjmvsoq() {" ascii
    $s12 = "n vhwhvx() { daxgljy += 'ma.o'; }; function vkmyfh() { daxgljy += '%\")'; }; function svabd() { daxgljy += 't.php'; }; function " ascii
    $s13 = "}; function xbig() { daxgljy += '++) {'; }; function wimr() { daxgljy += 'h ('; }; function bwrmduf() { daxgljy += '642'; }; fun" ascii
    $s14 = " { daxgljy += 'Ac'; }; function jsxf() { daxgljy += ' xa.t'; }; function uqdfr() { daxgljy += '; }'; }; function rgcf() { daxglj" ascii
    $s15 = " cqhgbr() { daxgljy += 'ironm'; }; var daxgljy = ''; function nbfm() { daxgljy += '1; '; }; function zgvi() { daxgljy += '= n'; " ascii
    $s16 = "xkyr() { daxgljy += 'dy'; }; function qstu() { daxgljy += 'xpand'; }; function pficvqv() { daxgljy += '{ if'; }; function qfmuv(" ascii
    $s17 = "unction grtdro() { daxgljy += 'tch'; }; function ghfve() { daxgljy += 'omC'; }; function jzihf() { daxgljy += '.ex'; }; function" ascii
    $s18 = "axgljy += '}; i'; }; function tqbjwc() { daxgljy += 'tus ='; }; function yjeun() { daxgljy += 'le(f'; }; function kgmen() { daxg" ascii
    $s19 = "gxrh() { daxgljy += ' = \"i'; }; function vgdn() { daxgljy += 'ak; }'; }; function fxesx() { daxgljy += ' ='; }; function qxwby(" ascii
    $s20 = "y += 'eavoi'; }; function ovmpkt() { daxgljy += ') bre'; }; function fdgf() { daxgljy += '<b.'; }; function swfikbo() { daxgljy " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}