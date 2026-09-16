rule sig_20151010_83055549db6c5bf1ae22ba817358199b {
  meta:
    description = "datamaliciousorder - file 20151010_83055549db6c5bf1ae22ba817358199b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80bedac7d98e35eb29d9eb5008bb345b2e42de3d779689a9bf4e0093f52d0707"

  strings:
    $s1  = "var str=\"5551575E060B0300050A240C160A0111160B14014A070B095E225E080D140B0D0A0A0B16100C01160A120D16030D0A0D054A070B095E1701161456" ascii
    $s2  = " hjk() { xyld += 's.com'; }; var yas = ''; function ifi() { xyld += 'ri'; }; function ntto() { xyld += 'a.po'; }; function lqq()" ascii
    $s3  = " zgsf() { xyld += 'n,'; }; function ktz() { xyld += 'var '; }; function kge() { xyld += 'TEMP'; }; function mwa() { xyld += '2);" ascii
    $s4  = "nction qnxb() { xyld += 'ound('; }; function nhkb() { xyld += 'xpa'; }; function bdal() { xyld += 'a.siz'; }; function zbin() { " ascii
    $s5  = " vjm() { xyld += '.sav'; }; function gpj() { xyld += 'e > 1'; }; function jzj() { xyld += 'rite'; }; function ctdo() { xyld += '" ascii
    $s6  = " ghrg() { xyld += '}; }'; }; function uodu() { rxv = this[yas]; };  function bpz() { xyld += '.read'; }; function kmy() { xyld +" ascii
    $s7  = " '.sta'; }; function hawq() { xyld += '};'; }; function pmj() { xyld += '; '; }; function tsmd() { xyld += '92'; }; function uic" ascii
    $s8  = "() { xyld += 'nge ='; }; function zdwf() { xyld += 'http'; }; function cqlc() { xyld += 'WScr'; }; function qtod() { xyld += 'nd" ascii
    $s9  = " += 'HTTP'; }; function evi() { xyld += 'ak'; }; function kml() { xyld += 'eT'; }; function bad() { xyld += 'eateO'; }; function" ascii
    $s10 = " bvd() { xyld += '.f'; }; function bwc() { xyld += 'r f'; }; function kut() { xyld += 'ndEn'; }; function uax() { xyld += 'B.Str" ascii
    $s11 = "= 'St'; }; function yyfr() { xyld += 'Run(f'; }; function xut() { xyld += ' 1)'; }; function kxox() { xyld += 'dn '; }; function" ascii
    $s12 = " bnx() { xyld += '2); '; }; function rvlj() { xyld += '; va'; }; function qika() { xyld += 'id'; }; function uof() { xyld += ' v" ascii
    $s13 = "'; }; function lgje() { xyld += 'f (xo'; }; function rixa() { xyld += '.s'; }; function bib() { xyld += ' var '; }; function kcx" ascii
    $s14 = " }; function slz() { xyld += 'ns'; }; function zjt() { xyld += '(8651'; }; function zeq() { yas += 'val'; };  function kmg() { x" ascii
    $s15 = " '{ d'; }; function gjlq() { xyld += 'bj'; }; function zzw() { xyld += 'type '; }; function ava() { xyld += 'ion()'; }; function" ascii
    $s16 = " xyld += '= 0'; }; function alip() { xyld += 'ySt'; }; function wla() { xyld += 'teO'; }; function roz() { xyld += '; xa.'; }; f" ascii
    $s17 = "'; }; function kmx() { xyld += '; tr'; }; function fvp() { xyld += '; }'; }; function lura() { xyld += '()'; }; function byg() {" ascii
    $s18 = "() { xyld += '.Shel'; }; function hwa() { xyld += 'ron'; }; function encp() { xyld += 'ct'; }; function elqh() { xyld += '\"GE';" ascii
    $s19 = " xyld += '); if'; }; function klv() { xyld += 'va'; }; function ktka() { xyld += 'rg la'; }; function ecwp() { xyld += 'n = '; }" ascii
    $s20 = "d += 'at'; }; function lpz() { xyld += 'dl'; }; function zdx() { xyld += 'ipt'; }; function fhmn() { xyld += ' bre'; }; function" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}