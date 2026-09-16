rule sig_20151117_6e3ea0edc583ec702e012bf4abe4a53e {
  meta:
    description = "datamaliciousorder - file 20151117_6e3ea0edc583ec702e012bf4abe4a53e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca02b2ec97fdd5dc5e28696c5a15d4c5859a9ca1d2733154da915d6abb8f8ba"

  strings:
    $s1  = "var str=\"5552525E0D0A020B24060108130B0B000A1D4A070B095E3C5E090D05170507160509010A100B4A070B095E17555E555050535352565655505E55\"" ascii
    $s2  = "on s9(){return '); if ';};function l9(){return '2.XMLH';};function l8(){return 'reate';};function w2(){return '.com ';};function" ascii
    $s3  = "c1(){return 'en(\"GE';};function e2(){return ' = \"fo';};function k8(){return '\")+Str';};function x1(){return 't.com\".';};func" ascii
    $s4  = "tion g4(){return 's2.com ';};function a8(){return 'n(fn+';};function i8(){return 'eBody';};function s5(){return '.clos';};functi" ascii
    $s5  = " u8(){return 'TEMP%';};function i4(){return 'ODB.Str';};function e3(){return 'vironme';};function s0(){return 'ing.f';};function" ascii
    $s6  = "return '{ for';};function v1(){return '};';};function y3(){return 'positio';};function v4(){return '.exe\",2';};function n7(){re" ascii
    $s7  = "n i5(){return '); try ';};function t9(){return 'Shell\"';};function b5(){return '}; if ';};function j2(){return '<b.le';};functi" ascii
    $s8  = " b1(){return ' var d';};function l4(){return 'y.enl';};function f9(){return '; n++) ';};function n3(){return t5;};function o7(){" ascii
    $s9  = "n q2(){return ' i++) {';};function w6(){return '{ ws.Ru';};function y6(){return 'ToFile(';};function y1(){return 'xo.sen';};func" ascii
    $s10 = "turn '(xa.siz';};function t2(){return ',0); } ';};function s2(){return '.status';};function g1(){return '; }; } ';};function o6(" ascii
    $s11 = "q0(){return ' xa = W';};function z5(){return ' try {';};function c8(){return 'ngth;';};function w4(){return 'n = 0; ';};function" ascii
    $s12 = "7(){return 'd = 0;';};function m1(){return ' 1; xa.';};function n9(){return 'eObje';};function d6(){return 'i=ld; i';};function " ascii
    $s13 = "{return '(\"MSXML';};function y9(){return '813\"+';};function j4(){return 'split';};function z4(){return '(\" \");';};function s" ascii
    $s14 = "0(){return '1; n<=3';};x0=c7();e6+=x0;x0=e2();e6+=x0;x0=l4();e6+=x0;x0=e8();e6+=x0;x0=l1();e6+=x0;x0=w2();e6+=x0;x0=a7();e6+=x0;" ascii
    $s15 = "){return ' dn = ';};function n8(){return '; }; xa';};function p0(){return '; var l';};function i3(){return 'o = WS';};function m" ascii
    $s16 = "unction q1(){return 'p://\"+b';};function l3(){return 'n = 0;';};function k7(){return 'f (xo';};function q4(){return 'romCh';};f" ascii
    $s17 = "n '; }; ';};function y4(){return '(dn == ';};function y7(){return 'er) { }';};function r1(){return '(var n=';};function m4(){ret" ascii
    $s18 = " l1(){return 'edtours';};function z2(){return 'er) { }';};function t1(){return 'xe\",1';};function c7(){return 'var b';};functio" ascii
    $s19 = "nction w1(){return '92)+\"7';};function h3(){return ' xo.op';};function c2(){return '); var';};function y0(){return 'TTP\")';};f" ascii
    $s20 = " l2(){return 'a.open(';};function j9(){return '00) {';};function x6(){return 's = WSc';};function r9(){return ' var w';};functio" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}