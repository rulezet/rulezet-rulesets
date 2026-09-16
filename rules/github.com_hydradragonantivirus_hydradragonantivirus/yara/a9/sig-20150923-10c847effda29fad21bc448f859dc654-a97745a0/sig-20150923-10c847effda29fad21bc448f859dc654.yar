rule sig_20150923_10c847effda29fad21bc448f859dc654 {
  meta:
    description = "datamaliciousorder - file 20150923_10c847effda29fad21bc448f859dc654.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba7d4cb790fae2c8eb9fa3310fcd8bc55998807e6407ceb1008b5a2773f53f2c"

  strings:
    $s1  = "var str=\"5550525E060B0300050A240C160A0111160B14014A070B09\";function cpnyoyl() { dnmykj += '.Exp'; }; function zkqpt() { dnmykj" ascii
    $s2  = "nction xfwxeh() { dnmykj += 't('; }; function opcri() { dnmykj += '.com'; }; function acyrllk() { dnmykj += 'cript'; }; function" ascii
    $s3  = "'000) '; }; function xkpctx() { dnmykj += 'fr'; }; function bzik() { dnmykj += 'ady'; }; function xyube() { dnmykj += '\"GET'; }" ascii
    $s4  = "nmykj += 's = '; }; function xxks() { dnmykj += ' v'; }; function jmsbr() { dnmykj += '.sta'; }; function qywnvja() { dnmykj += " ascii
    $s5  = " 'php?'; }; function bllgot() { dnmykj += ' 0; v'; }; function rpom() { dnmykj += ',0); '; }; function wvwn() { dnmykj += 'o.rea" ascii
    $s6  = "var str=\"5550525E060B0300050A240C160A0111160B14014A070B09\";function cpnyoyl() { dnmykj += '.Exp'; }; function zkqpt() { dnmykj" ascii
    $s7  = "ion dlzmmh() { dnmykj += '.clo'; }; function zssrhsd() { dnmykj += 'rea'; }; function idrnzu() { dnmykj += 'st'; }; function wbu" ascii
    $s8  = "ction obztbmu() { dnmykj += ' if'; }; function jbsybl() { dnmykj += 'h.rou'; }; function ptzfn() { dnmykj += '{ ws'; }; function" ascii
    $s9  = " }; function ziwk() { dnmykj += 'mpio'; }; function htxo() { dnmykj += '(8323'; }; function ddzxb() { dnmykj += 'iveX'; }; funct" ascii
    $s10 = "() { dnmykj += 'h.ra'; }; function yejj() { dnmykj += 'ar '; }; function xexoia() { dnmykj += 'ate'; }; function pduc() { dnmykj" ascii
    $s11 = "'plit('; }; function xscsmz() { dnmykj += 'b.le'; }; function pbdh() { dnmykj += 'un'; }; function qieoyg() { dnmykj += '++) {';" ascii
    $s12 = "'new A'; }; function rihrwl() { dnmykj += 'pen'; }; function airfe() { dnmykj += 'dl('; }; function hpkcp() { dnmykj += 'gs(\"';" ascii
    $s13 = "mykj += 'e '; }; function rrswqec() { dnmykj += '.op'; }; function eitjjk() { dnmykj += 'nre'; }; function okyd() { dnmykj += 'o" ascii
    $s14 = " function zksxbu() { dnmykj += 'ject'; }; function srkddkg() { dnmykj += '); v'; }; function ctjfwni() { dnmykj += ' = '; }; fun" ascii
    $s15 = "ix() { dnmykj += ' };'; }; function hxjq() { dnmykj += '); '; }; function gfuusak() { dnmykj += '; x'; }; function rtorfo() { dn" ascii
    $s16 = "unction aakwzd() { dnmykj += '10000'; }; function bfcvp() { dnmykj += '); xo'; }; function vxgp() { dnmykj += '00)+'; }; functio" ascii
    $s17 = "+= 'e'; };  function esae() { dnmykj += 'nvir'; }; function hbvnta() { dnmykj += 'nd()'; }; function fttq() { dnmykj += 'gue.c';" ascii
    $s18 = "}; function wwuso() { dnmykj += '}; '; }; var dnmykj = ''; function lvbjh() { dnmykj += 'nsh'; }; function whpec() { dnmykj += '" ascii
    $s19 = "= '; va'; }; function trlv() { dnmykj += ' xa.t'; }; function xpryrml() { dnmykj += '> 5'; }; function pfqglf() { dnmykj += 'XML" ascii
    $s20 = "n rqgcoiv() { dnmykj += '(Mat'; }; function mvwz() { dnmykj += 'Obje'; }; function hzhogw() { dnmykj += ' &&'; }; function ugvsu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}