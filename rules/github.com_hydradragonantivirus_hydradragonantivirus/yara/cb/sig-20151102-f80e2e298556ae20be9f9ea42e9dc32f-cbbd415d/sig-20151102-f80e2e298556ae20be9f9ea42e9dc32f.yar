rule sig_20151102_f80e2e298556ae20be9f9ea42e9dc32f {
  meta:
    description = "datamaliciousorder - file 20151102_f80e2e298556ae20be9f9ea42e9dc32f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e8bf8d98e03235f5c3a1dbe1e578fa37267a6867460714c54bc9837bdfd0b83"

  strings:
    $s1  = "var str=\"5552565E0905160F01100D0A03240C160A0111160B14014A070B095E3C5E170B080B491005160E011005174A070B094A091C5E17555E5550505257" ascii
    $s2  = "eturn '+n+\".ex';};function d3(){return '= WSc';};function z5(){return 'e.com\"';};function a0(){return '3; n+';};function t9(){" ascii
    $s3  = "0(){return 'bject(';};function x5(){return '.com yo';};function r8(){return 'ar xa';};function j7(){return 'tch (e';};function w" ascii
    $s4  = "0(){return 'respon';};function m3(){return 'DB.Str';};function l4(){return '%TEMP';};function e4(){return '; };';};function i9()" ascii
    $s5  = "tion v1(){return ' ws.Ru';};function m6(){return '+\".exe';};function l1(){return 'open(';};function g9(){return 'a.open';};func" ascii
    $s6  = "return 'SXML2.';};function u9(){return 'rnd=30';};function z1(){return '\"GET\"';};function z0(){return 'var ld';};function z7()" ascii
    $s7  = "eturn 't.Shell';};function w3(){return '.type ';};function x7(){return 'or (v';};function j2(){return '+) { f';};function v7(){r" ascii
    $s8  = "6(){return 'o.sen';};function i3(){return 'tatus =';};function z6(){return 'saveTo';};function k2(){return 'seBody';};function r" ascii
    $s9  = "eturn ' { ld';};function i4(){return ',\"http:';};function i6(){return 's.Expa';};function g0(){return 'n(fn+n';};function n3(){" ascii
    $s10 = "return 'File(fn';};function u4(){return 'com.br';};function f0(){return 'e(); };';};function v2(){return ' dn = ';};function w0(" ascii
    $s11 = "turn ' (xo.s';};function t5(){return '\" \"); v';};function f2(){return '1; xa.';};function t1(){return '(var n';};function c8()" ascii
    $s12 = "eturn ' = \"r';};function j3(){return 'ject(\"M';};function h7(){return 'posit';};function h0(){return 'n == 1)';};function m5()" ascii
    $s13 = "urn 'd(); if';};function w8(){return 'cript.';};function h9(){return '.split(';};function g8(){return 'reateOb';};function m4(){" ascii
    $s14 = "eturn '?id=\"+';};function o1(){return ', fal';};function t0(){return '= 1; xa';};u5+=s1();u5+=n3();u5+=f4();u5+=u4();u5+=m4();u" ascii
    $s15 = "{return 'Creat';};function f4(){return 'ambh.';};function e1(){return 'XMLHT';};function b3(){return '; try {';};function q8(){r" ascii
    $s16 = "turn 'ze > 10';};function c4(){return 'ar i=ld';};function s1(){return 'var b';};function g4(){return 'eam\"); ';};var u5 = '';f" ascii
    $s17 = "rn 'CharC';};function m8(){return 'ript.C';};function m2(){return '57\"; va';};function e3(){return '; i<b.l';};function o0(){re" ascii
    $s18 = "){return 'ings(\"';};function v3(){return '); if ';};function d2(){return '(\"ADO';};function k7(){return 'e(xo.';};function h2(" ascii
    $s19 = "{return 'ndEnv';};function f9(){return 'ode(92';};function s3(){return '\",1,0)';};function k8(){return 'ntStr';};function h5(){" ascii
    $s20 = "return ' j-hsu';};function x9(){return ' = 0;';};function a4(){return ')+\"9738';};function q7(){return 'TP\"); v';};function d8" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}