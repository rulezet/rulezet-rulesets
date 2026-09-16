rule sig_20151104_f298742aca1ed78b50aaf67da89bc725 {
  meta:
    description = "datamaliciousorder - file 20151104_f298742aca1ed78b50aaf67da89bc725.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9d86be7783516c1e78b542fe0de185adcb432316b7ba8a9806652414400d405"

  strings:
    $s1  = "var str=\"5552505E160D1005240C160A0111160B14014A070B095E3C5E0905100C11160506110D08000116174A070B4A0D0A5E17555E5550505252515C5052" ascii
    $s2  = "j';};function y3(){return '; xa.';};function k9(){return 'ream\")';};function l6(){return 'veToF';};function z3(){return 'r.com'" ascii
    $s3  = ";function i2(){return 'm\".spl';};function t6(){return ' if (';};function z6(){return 'Script';};function r5(){return 'xo.ope';}" ascii
    $s4  = "tion o5(){return 'xo.se';};function d3(){return '.posit';};function u0(){return '; var w';};function q4(){return 'n+\".exe';};fu" ascii
    $s5  = "s = WS';};function w8(){return '+String';};function f6(){return 'TEMP%\")';};function x1(){return ' 200) ';};function n2(){retur" ascii
    $s6  = "o.res';};function m0(){return 'com liv';};function p2(){return eval;};function k5(){return '> 1000';};function h4(){return 'teOb" ascii
    $s7  = "n 'harCod';};function v2(){return 'Run(fn+';};function r6(){return '; xa.wr';};function h6(){return 'edy.sit';};function l0(){re" ascii
    $s8  = "return 'n(\"GET';};function a2(){return 'i; bre';};function s4(){return 'er) { ';};function j9(){return '\"&rnd=';};function e5(" ascii
    $s9  = "n 'ect(\"A';};function d1(){return 'Shell\")';};function l1(){return '; var';};function g2(){return 'f (xa';};function n7(){retu" ascii
    $s10 = "tion u5(){return 'vironme';};function j4(){return 'i<b.len';};function v6(){return 'ry { ';};function s8(){return '; for (';};fu" ascii
    $s11 = "function r3(){return ' };';};function e6(){return '); } ';};function t9(){return 'pt.Cre';};function z4(){return 'ript.';};funct" ascii
    $s12 = "return '://\"+b';};function g6(){return ' \"kenn';};function l7(){return 'xpandEn';};function h8(){return ' xa.typ';};function w" ascii
    $s13 = "};function h2(){return 'ile(f';};function o8(){return 'xo = W';};function y6(){return '{ for';};function t3(){return '\",\"http'" ascii
    $s14 = " '338102\"';};function h5(){return '; n<=3';};function c5(){return 'MLHTTP\"';};function e0(){return 'exe\",2)';};function r7(){" ascii
    $s15 = "urn 'gth; i+';};function b1(){return '}; };';};function s1(){return '== 1) {';};function j1(){return 'us ==';};function f1(){ret" ascii
    $s16 = "rn '; n++) ';};function q3(){return 'e = 1';};function y1(){return '\"+str+';};function e1(){return '{ xa.';};function h9(){retu" ascii
    $s17 = "){return '= WScri';};function a7(){return 'if (dn ';};function f7(){return 'r xa ';};function i6(){return 'xo.stat';};function a" ascii
    $s18 = "ion b8(){return 'ion = 0';};function g9(){return 'e(92)+\"';};function b6(){return 'ak; }';};function y7(){return 'eoakres';};fu" ascii
    $s19 = "urn ' fn =';};function a4(){return ' ws.E';};function b5(){return ' (er) {';};function t5(){return 'tch (';};function e8(){retur" ascii
    $s20 = "ction q1(){return 'se); ';};function k6(){return 'DODB.St';};function b9(){return 'n+n+\".';};function g8(){return '; var';};fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}