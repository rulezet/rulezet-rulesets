rule sig_20151013_c29678e83b62c88c590848e86e4529df {
  meta:
    description = "datamaliciousorder - file 20151013_c29678e83b62c88c590848e86e4529df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b67485bebd7d9c614fda73f0e6c6228383a26a16c80aa182f2a71b6ff40b4ef"

  strings:
    $s1  = "var str=\"5551575E060B0300050A240C160A0111160B14014A070B095E225E0B1E09010A490810004A070B095E17011614565E5550505053545D555555\"; " ascii
    $s2  = " { vbv += 'ar '; }; function dfi() { vbv += 'GET'; }; function czvk() { vbv += 'ool.'; }; function hbro() { vbv += '[i]+\"'; }; " ascii
    $s3  = "'; }; function kzyd() { vbv += 'func'; }; function cxrc() { vbv += 'send'; }; function nqda() { vbv += 'Run'; }; function vams()" ascii
    $s4  = "j'; }; function dvl() { vbv += ' dl(4'; }; function mmz() { vbv += '.s'; }; function lvw() { vbv += 'rando'; }; function key() {" ascii
    $s5  = " lker() { vbv += 's v'; }; function jpzx() { vbv += 'h.r'; }; function pfm() { vbv += '&& xo'; }; function nlnh() { vbv += '.wri" ascii
    $s6  = "'; }; function nsd() { vbv += 'nread'; }; function mnix() { vbv += 'fun'; }; function rnvi() { vbv += '83);'; }; function wbab()" ascii
    $s7  = "v += '; } c'; }; function vsi() { vbv += '1)'; }; function lpm() { vbv += 'read'; }; function ump() { vbv += ' bre'; }; function" ascii
    $s8  = " }; function hfs() { vbv += 'e\"; v'; }; function babn() { vbv += 'lo'; }; function pfjd() { vbv += 'xa.si'; }; function wiyb() " ascii
    $s9  = " ufpb() { vbv += '{ dn'; }; function hpyq() { vbv += 'dl(68'; }; function qexs() { vbv += '{ va'; }; function dbv() { vbv += '10" ascii
    $s10 = "'Creat'; }; function tis() { vbv += 'en(\"'; }; function vzkk() { vbv += 'oy.co'; }; function cssp() { vbv += ' t'; }; function " ascii
    $s11 = " { vbv += 'ADOD'; }; function tkkd() { vbv += 'pa'; }; function krd() { vbv += 'org'; }; function veqn() { vbv += ' d'; }; funct" ascii
    $s12 = "ion flh() { vbv += ');'; }; function ips() { vbv += 'Ma'; }; function mpik() { vbv += '92'; }; function xtls() { vbv += 'ystat';" ascii
    $s13 = "'Bo'; }; function zbv() { vbv += 'var'; }; function ubax() { vbv += ' 1;'; }; function ysx() { vbv += ' i=0'; }; function kxv() " ascii
    $s14 = " { vbv += '2.X'; }; function ajlb() { vbv += '; };'; }; function vrr() { vbv += 'larb'; }; function fbb() { vbv += '; i<b'; }; f" ascii
    $s15 = "iwr += 'e'; };  function njuv() { vbv += '; };'; }; function tqw() { vbv += 't.Cr'; }; function lxd() { vbv += 'ct'; }; function" ascii
    $s16 = "unction gnpg() { vbv += ')+Str'; }; function zdkd() { vbv += 'ws.Ex'; }; function rps() { vbv += 'e);'; }; function wne() { vbv " ascii
    $s17 = " { vbv += 'atch '; }; function ampr() { vbv += ' };'; }; function hyl() { vbv += '; '; }; function gsos() { vbv += 'l(11'; }; fu" ascii
    $s18 = "; }; function grn() { vbv += 'p://'; }; function pywe() { vbv += ' = W'; }; function lrp() { vbv += 'atch '; }; function wji() {" ascii
    $s19 = " }; function mri() { vbv += 't.Cr'; }; function njpc() { vbv += 'm\");'; }; function qzmn() { vbv += 'prak'; }; function phoa() " ascii
    $s20 = "t'; }; function claj() { vbv += 'WS'; }; function hzq() { vbv += 'Scri'; }; function zbx() { vbv += 'ww'; }; function tnv() { vb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}