rule sig_20151101_496eda5b1beb2d694d85cd059a13c96a {
  meta:
    description = "datamaliciousorder - file 20151101_496eda5b1beb2d694d85cd059a13c96a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a348a127fab815bafbc977323e4c808af25ebe1e1a116eec88a896539129f803"

  strings:
    $s1  = "var str=\"5552565E0C160A240C161001070C0508080D050A0701174A070B095E3C5E050701491407064A0A01105E17575E55505052575C515055505E55\"; " ascii
    $s2  = " ibz() { dwa += 'ings('; }; function kryt() { dwa += '++) '; }; function nxx() { dwa += '.Run'; }; function whmu() { dwa += '); " ascii
    $s3  = "ction xkj() { dwa += '\")+'; }; var ctja = ''; function wstc() { dwa += '\"GET\"'; }; function jfmm() { dwa += 'str+'; }; functi" ascii
    $s4  = "{ dwa += 'DODB'; }; function ivh() { dwa += 're'; }; function sng() { dwa += 'com'; }; function sgo() { dwa += 'va'; }; function" ascii
    $s5  = " }; function edn() { dwa += '; v'; }; function zvz() { dwa += 'com'; }; function ddn() { dwa += '; xa'; }; function bopf() { dwa" ascii
    $s6  = ".Cr'; }; function nssb() { dwa += '\".spl'; }; function coy() { dwa += 'ar i='; }; function lzt() { dwa += 'r)'; }; function pxp" ascii
    $s7  = "}; function nzf() { dwa += 'e('; }; function nqp() { dwa += 'n+n+'; }; function qmx() { dwa += '.ope'; }; function xoj() { dwa +" ascii
    $s8  = " dwa += 'Stri'; }; function rtba() { dwa += 'oa'; }; function cmdx() { dwa += '.type'; }; function tui() { dwa += '\"%TE'; }; fu" ascii
    $s9  = "aw() { dwa += ' { };'; }; function mwy() { dwa += '{ l'; }; function hdqw() { dwa += 'i<b'; }; function nvlh() { dwa += '.Str'; " ascii
    $s10 = "; '; }; function oehb() { dwa += '.sen'; }; function vby() { dwa += 'ar xa'; }; function lcf() { dwa += 'xa.si'; }; function zgv" ascii
    $s11 = "'d ='; }; function dbe() { dwa += 'for '; }; function hlt() { dwa += '); xa'; }; function afz() { dwa += 'en('; }; function kzun" ascii
    $s12 = " }; function sqg() { dwa += ') '; }; function kssu() { dwa += 'ak;'; }; function ahf() { dwa += ' c'; }; function ijkq() { dwa +" ascii
    $s13 = "nction fxp() { dwa += '\"+'; }; function xzvz() { dwa += 'WScr'; }; function ufg() { dwa += ' ld'; }; function wyuz() { dwa += '" ascii
    $s14 = "unction jnin() { dwa += '; i'; }; function rpde() { dwa += '= \"y'; }; function dqx() { dwa += ' v'; }; function lluu() { dwa +=" ascii
    $s15 = "ion hbyv() { dwa += '2263'; }; function uafk() { dwa += 'd();'; }; function fzp() { dwa += ' }; '; }; function jpqc() { dwa += '" ascii
    $s16 = "ion dwjh() { dwa += ' i;'; }; function rhs() { dwa += 'n, f'; }; function niio() { dwa += '; '; }; function klp() { dwa += 'it';" ascii
    $s17 = " { dwa += ' = '; }; function acmh() { dwa += ') {'; }; function phw() { dwa += 'xo.r'; }; function pmz() { dwa += '{ '; }; funct" ascii
    $s18 = "n qjl() { dwa += 'atc'; }; function utxa() { dwa += ' n'; }; function lih() { dwa += 'n ='; }; function upwo() { dwa += 'Cre'; }" ascii
    $s19 = "'; }; function vwr() { dwa += 'ro'; }; function lcnl() { dwa += '); v'; }; function nkuc() { dwa += 'ry {'; }; function kgdh() {" ascii
    $s20 = "{ dwa += '\"+b['; }; function fgxw() { dwa += ' 1; '; }; function iyd() { dwa += 'f (xo'; }; function qaiw() { dwa += 'om'; }; f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}