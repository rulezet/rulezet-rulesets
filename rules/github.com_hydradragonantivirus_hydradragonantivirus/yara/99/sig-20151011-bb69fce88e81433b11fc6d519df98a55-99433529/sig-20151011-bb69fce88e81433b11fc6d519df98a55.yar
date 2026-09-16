rule sig_20151011_bb69fce88e81433b11fc6d519df98a55 {
  meta:
    description = "datamaliciousorder - file 20151011_bb69fce88e81433b11fc6d519df98a55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae6b82b37c48b04fb1512a153a752056e68fcfca528f0de9a936c23b974f0b32"

  strings:
    $s1  = "var str=\"5551575E0D0A020B24011C1405101001070C4A070B095E225E0C0B1714080506100B4A070B094A06165E17011614565E55505050515650565D50\"" ascii
    $s2  = "tion plr() { qcp += 'posi'; }; function pwvh() { qcp += '\"GET\"'; }; function mzft() { qcp += ' var'; }; function drs() { qcp +" ascii
    $s3  = "p += ')+\".e'; }; function pgq() { qcp += 'er/?i'; }; function iap() { qcp += '.rand'; }; function wbxp() { qcp += 'com'; }; fun" ascii
    $s4  = "'; }; function yct() { qcp += ' v'; }; function dduj() { qcp += 'or'; }; function erql() { qcp += 't.Cre'; }; function pmm() { q" ascii
    $s5  = "() { qcp += 'l.'; }; function qzvt() { qcp += 'com.'; }; function cwu() { qcp += 'ateOb'; }; function oit() { qcp += ');'; }; fu" ascii
    $s6  = "+= 'm\"); '; }; function vpfs() { qcp += 'e = 1'; }; function ryx() { qcp += '11);'; }; function awl() { qcp += '.Cre'; }; funct" ascii
    $s7  = "function bax() { qcp += 'f '; }; function vkbo() { qcp += 'pt.S'; }; function txp() { qcp += '.onr'; }; function ylqw() { qcp +=" ascii
    $s8  = "= 'sa'; }; function jjft() { qcp += ' ='; }; function vqds() { qcp += 'se'; }; function yhzs() { qcp += '.typ'; }; function wsqq" ascii
    $s9  = "= '(xo.r'; }; function kdp() { qcp += 'B.St'; }; function rppp() { qcp += 'ha'; }; function kor() { qcp += 'ar'; }; function mgb" ascii
    $s10 = "e() { qcp += 'id'; }; function fqa() { qcp += 'he'; }; function txo() { qcp += 'us'; }; function pte() { qcp += '(xo.R'; }; func" ascii
    $s11 = "u() { qcp += 'Scrip'; }; function seew() { qcp += '+fr, '; };fxr(); dvrm(); aype(); wsqq(); lyda(); olqr(); llv(); cks(); mgk();" ascii
    $s12 = "; i'; }; function bhbu() { qcp += '00000'; }; function avw() { qcp += ' }; '; }; function peo() { qcp += 's.E'; }; function lqp(" ascii
    $s13 = " qcp += 'l(17'; }; function qqh() { qcp += '(v'; }; function ntmg() { qcp += 'icsc'; }; function qtha() { qcp += '\");'; }; func" ascii
    $s14 = "ction gyf() { qcp += 'cna'; }; function xptn() { qcp += 'ateO'; }; function itso() { qcp += ' };'; }; function laf() { qcp += 'l" ascii
    $s15 = "() { qcp += 'l(fr'; }; function xpo() { qcp += 'ate'; }; function rks() { qcp += 'i<b.'; }; function wcpu() { qcp += 'try '; }; " ascii
    $s16 = ") { qcp += 'shp'; }; function sen() { qcp += 'und(M'; }; function vuz() { qcp += '3);'; }; function oasy() { qcp += 'via'; }; fu" ascii
    $s17 = ") { qcp += '000)'; }; var qcp = ''; function zaxy() { qcp += 's.'; }; function kbbm() { qcp += '0; '; }; function scrm() { qcp +" ascii
    $s18 = "engt'; }; function iyml() { qcp += 'yapr'; }; function lpj() { qcp += 'tion'; }; function wenx() { qcp += '{ xo.'; }; function p" ascii
    $s19 = "tion hhl() { qcp += 'si'; }; function fion() { nlot += 'val'; };  function kkm() { qcp += 'ToFil'; }; function bore() { qcp += '" ascii
    $s20 = " }; function bkzt() { qcp += 'e ='; }; function aje() { qcp += '; '; }; function yyq() { qcp += '++)'; }; function pvz() { qcp +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}