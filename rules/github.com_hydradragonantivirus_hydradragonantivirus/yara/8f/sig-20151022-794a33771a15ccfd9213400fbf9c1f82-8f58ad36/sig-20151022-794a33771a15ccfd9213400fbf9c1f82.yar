rule sig_20151022_794a33771a15ccfd9213400fbf9c1f82 {
  meta:
    description = "datamaliciousorder - file 20151022_794a33771a15ccfd9213400fbf9c1f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8078a5a65ef8e76eeef569fbe6465c2dc92447922fccee89d33b161421bfa501"

  strings:
    $s1  = "nction nktv() { xmgt += 'dy)'; }; function iuwc() { xmgt += 'm\"'; }; function wes() { xmgt += '.res'; }; function jlkx() { xmgt" ascii
    $s2  = "t += 'HTTP\"'; }; function vbgw() { xmgt += '; xa.'; }; function dsg() { xmgt += 'xa.'; }; function wwsg() { xmgt += '1; x'; }; " ascii
    $s3  = "+= '= \"ww'; }; function ngek() { xmgt += 'n(\"GE'; }; function lyr() { xmgt += 'r.co'; }; function eym() { xmgt += 'o.ope'; }; " ascii
    $s4  = "gt += '9\";'; }; function fqw() { xmgt += 'ode'; }; function mez() { xmgt += 'teO'; }; function jxcj() { xmgt += '2.XML'; }; fun" ascii
    $s5  = " '3; '; }; function dqb() { xmgt += 'n ='; }; function axlo() { xmgt += '.Exp'; }; function tqlk() { xmgt += 'va'; }; function o" ascii
    $s6  = "var str=\"55515C5E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E275E0E0E010A03010A0C05160D054A070B095E17555E55505051" ascii
    $s7  = "nction nbu() { xmgt += 'w.fl'; }; function wpc() { xmgt += 'ect'; }; function ykb() { xmgt += 'va'; }; function kwcx() { xmgt +=" ascii
    $s8  = " 'pt.'; }; function vxp() { xmgt += 'izeit'; }; function neq() { xmgt += 's.co'; }; function kex() { xmgt += ',2); '; }; functio" ascii
    $s9  = "{ xmgt += ' (e'; }; function afte() { xmgt += 'r '; }; function cdo() { xmgt += 'diver'; }; function sorp() { xmgt += ' }; '; };" ascii
    $s10 = " xmgt += 'Scri'; }; function ulnz() { xmgt += 'tch ('; }; function snna() { xmgt += 'itio'; }; function ojoc() { xmgt += 'ODB.';" ascii
    $s11 = "ion yjv() { xmgt += 'ript'; }; function ysle() { ffn = this; };  function cvz() { xmgt += 'writ'; }; function hgi() { xmgt += '" ascii
    $s12 = "on zee() { xmgt += 'd='; }; function nev() { xmgt += 'var '; }; function paxu() { xmgt += 'r b '; }; function nuy() { xmgt += 'W" ascii
    $s13 = "gt += 'er) '; }; function kngd() { xmgt += 'fa'; }; function biwx() { xmgt += '; n<='; }; function qcz() { xmgt += ' xo '; }; fu" ascii
    $s14 = "'e(xo'; }; function rna() { xmgt += ' w'; }; function dihr() { xmgt += '\".e'; }; function knkj() { xmgt += 'exe\"'; }; function" ascii
    $s15 = "'; }; function psbq() { xmgt += ' ='; }; function pen() { xmgt += 'lose('; }; function kicg() { xmgt += 'p://'; }; function sske" ascii
    $s16 = "; }; function yvzi() { xmgt += '); v'; }; function xwi() { xmgt += '.type'; }; function vuv() { xmgt += ' }'; }; var xmgt = ''; " ascii
    $s17 = "+= ' ld '; }; function dwc() { xmgt += 'reak;'; }; function lxbz() { xmgt += '.se'; }; function aux() { xmgt += 'lse)'; }; funct" ascii
    $s18 = "Scr'; }; function hxd() { xmgt += 'mentS'; }; function mmb() { xmgt += 'te'; }; function xpor() { xmgt += 'an'; }; function iqia" ascii
    $s19 = "t += 'Cre'; }; function uqj() { xmgt += 'open('; }; function hfdd() { xmgt += ']+'; }; function qvy() { xmgt += '0)'; }; functio" ascii
    $s20 = "xmgt += ' { '; }; function edqy() { xmgt += 'm\".sp'; }; function mqkx() { xmgt += '(\"%TE'; }; function lmcq() { xmgt += '1,0';" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}