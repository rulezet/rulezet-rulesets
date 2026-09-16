rule sig_20151111_adbed14eddb0468703c57e00bc1d20f1 {
  meta:
    description = "datamaliciousorder - file 20151111_adbed14eddb0468703c57e00bc1d20f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "718b4bb3c9e4454870d2699cae1573c99e30432519019a83a00251703a063978"

  strings:
    $s1  = "var str=\"5552505E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E3C5E090B0A050911164A070B095E17555E555050535656545757" ascii
    $s2  = " i=ld;';};function e2(){return ' i; br';};function g0(){return '%TEMP%\"';};function d4(){return 'write(';};function a7(){return" ascii
    $s3  = "return ' var x';};function n6(){return 'Object(';};function i2(){return '.com m';};function f0(){return 'h (er';};function u1(){" ascii
    $s4  = "eturn 'ngs(\"';};function k3(){return 'o.statu';};function c2(){return 's.com\".';};function m5(){return 'cnair';};function d0()" ascii
    $s5  = "l\"); v';};function s1(){return 'i++) { ';};function e6(){return 'ipt.C';};function t7(){return 'en(\"GET';};function l2(){retur" ascii
    $s6  = " fn =';};function y4(){return ',2); tr';};function z5(){return '{ for';};function q0(){return 'Run(fn';};function w6(){return ' " ascii
    $s7  = "{return '} catch';};function g3(){return '200) { ';};function z6(){return '.exe\"';};function t5(){return 'r xa =';};function i9" ascii
    $s8  = "eturn 'a.typ';};function q2(){return 'xo.res';};function y8(){return ')+Strin';};function r4(){return 'xpandEn';};function m8(){" ascii
    $s9  = "eak; };';};function d7(){return 'xa.siz';};function u5(){return '; if ';};function f9(){return '(); x';};function w3(){return 'v" ascii
    $s10 = "n<=3;';};function t2(){return 'xa.open';};function o2(){return '\",\"http';};function u9(){return '(\" \"); ';};function l4(){re" ascii
    $s11 = "eturn ' WScri';};function y7(){return ' ws.E';};function s9(){return ' xa.clo';};function e4(){return 'n, fals';};function h7(){" ascii
    $s12 = " 'var dn';};function d3(){return '+n+\".';};function n2(){return 'LHTTP';};function n5(){return ' n++) ';};function t1(){return " ascii
    $s13 = "\"+str+\"';};function x4(){return 'WScrip';};function a9(){return 'ntStri';};function q4(){return '; xa.';};function t3(){return" ascii
    $s14 = "'ct(\"AD';};function c8(){return '; if (x';};function c5(){return 'ength; ';};function a1(){return ' ld =';};function j0(){retur" ascii
    $s15 = "){return ' = 1;';};function p5(){return '.send()';};f2+=t9();f2+=g2();f2+=i7();f2+=g7();f2+=g8();f2+=j4();f2+=i2();f2+=m5();f2+=" ascii
    $s16 = "{return ' i<b.l';};function h3(){return 'o = WSc';};function o9(){return 'Create';};function j6(){return '0) { dn';};function o4" ascii
    $s17 = " ') { };';};function m0(){return 'harCode';};function m3(){return '&rnd=27';};function s3(){return eval;};function n3(){return '" ascii
    $s18 = " '(dn ==';};function g9(){return 'aveTo';};function u8(){return ' xa.s';};function z1(){return ' xo.op';};function a0(){return '" ascii
    $s19 = "55E55\";function g8(){return 'incolnr';};function g5(){return 'r n=1;';};function b4(){return '\"); va';};function r3(){return '" ascii
    $s20 = " 'r/?id=';};function y6(){return ' }; };';};function n7(){return 'bject(\"';};function q1(){return 'teObje';};function p3(){retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}