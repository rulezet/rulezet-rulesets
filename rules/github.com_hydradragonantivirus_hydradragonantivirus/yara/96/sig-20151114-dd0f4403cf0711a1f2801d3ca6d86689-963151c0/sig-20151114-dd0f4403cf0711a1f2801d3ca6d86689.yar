rule sig_20151114_dd0f4403cf0711a1f2801d3ca6d86689 {
  meta:
    description = "datamaliciousorder - file 20151114_dd0f4403cf0711a1f2801d3ca6d86689.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b0d03d5154b86008ef4c006aa28509f0ee9b0afb8f679ce0239d3180aab83b0"

  strings:
    $s1  = "var str=\"5552525E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E3C5E15110117100D0B0A170D030A4A16115E17555E5550505350" ascii
    $s2  = "return '%TEMP%\"';};function f8(){return 'ntStri';};function n0(){return 'eObjec';};function j0(){return g2;};function o7(){retu" ascii
    $s3  = ".exe\",2';};function l8(){return '.saveT';};function l5(){return '=ld; ';};function k9(){return 'a.wri';};function e5(){return '" ascii
    $s4  = "\".exe\"';};function g1(){return 'oFile(f';};function r1(){return 'ter/?i';};function f2(){return '.resp';};function v3(){return" ascii
    $s5  = "ODB.Str';};function p0(){return 'status';};function d6(){return 'f (xo.';};function c8(){return 'ngth;';};function g4(){return '" ascii
    $s6  = "; var';};function a8(){return 'Script';};function z9(){return 't(\"AD';};function x1(){return ')+Str';};function v6(){return '92" ascii
    $s7  = "eturn '\"/coun';};function f5(){return 'LHTTP\")';};function h0(){return 'dn == 1';};function d9(){return 'bject(';};function l3" ascii
    $s8  = "lse);';};var r7='';var g2=eval;var j6='';function e2(){return 'xa.pos';};function d3(){return 'tr+\"&rn';};function l7(){return " ascii
    $s9  = "{return 'ET\",\"ht';};function c9(){return 'port.';};function h8(){return ' if (x';};function p5(){return 'L2.XM';};function i7(" ascii
    $s10 = "0;';};function t3(){return 'eObjec';};function o1(){return 'xo = ';};function q0(){return 's.Exp';};function u7(){return ' xo.se" ascii
    $s11 = "fn+n+';};function m4(){return 'n+n+\"';};function k0(){return 'esort.c';};function n2(){return 'hell\")';};function y7(){return " ascii
    $s12 = "r';};function c6(){return 'te(xo';};function w5(){return 'net n';};function z5(){return 'ar ws ';};function h1(){return '; var';" ascii
    $s13 = "pen(';};function g3(){return 'eoakr';};function k4(){return 'eam\")';};function v8(){return '= WScr';};function u8(){return ') {" ascii
    $s14 = "n';};function a2(){return 'ition ';};function b5(){return '); try ';};function s6(){return '; if (';};function g8(){return '\"WS" ascii
    $s15 = "fn = w';};function t6(){return '(var n';};function v9(){return '<=3; ';};function u5(){return ') { ld ';};function a0(){return '" ascii
    $s16 = " for ';};function d8(){return '63\"+n, ';};function z2(){return '\" \"); v';};function o3(){return 'e(); }';};function w2(){retu" ascii
    $s17 = "turn 't.Creat';};function o4(){return 'i<b.le';};function q1(){return '= \"club';};function d0(){return '.clos';};function y6(){" ascii
    $s18 = "onme';};function q7(){return 'a.size';};function v1(){return '; } c';};function n1(){return ' 1; x';};function h5(){return 'n = " ascii
    $s19 = "eturn 'tp://\"+';};function a1(){return ' try {';};function d7(){return '=1; n';};function y9(){return ' ld = ';};function e6(){" ascii
    $s20 = "d=6716';};function q9(){return '); xa';};function n8(){return 'r) { }';};function w3(){return '.type =';};function h6(){return '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}