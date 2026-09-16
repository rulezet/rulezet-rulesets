rule sig_20151104_c5a37f6ee4598c6bd3bcdcd27c7731ba {
  meta:
    description = "datamaliciousorder - file 20151104_c5a37f6ee4598c6bd3bcdcd27c7731ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7693a91d977e4c33592eb751672b6103f867322fc354c93144f19644d3c5a75a"

  strings:
    $s1  = "var str=\"5552505E17050D0005240C160A0111160B14014A070B095E3C5E0D0A10011603010B120A4A070B095E17555E5550505252515C5052515E55\";fun" ascii
    $s2  = "on z6(){return '1; n<=';};function d4(){return '.com\".';};function t4(){return '+n, fa';};function b9(){return 'P\"); v';};func" ascii
    $s3  = "rn '%TEMP';};function l4(){return 'eObject';};function p5(){return ' ld = i';};function r7(){return '= WSc';};function g1(){retu" ascii
    $s4  = "e4(){return 'WScript';};function g2(){return 'ar fn ';};function y0(){return ']+\"/c';};function s4(){return '+n+\".ex';};functi" ascii
    $s5  = "w4(){return '.Run(fn';};function j6(){return '.leng';};function z7(){return 'e\",1,0';};function q3(){return ' (er)';};function " ascii
    $s6  = "3(){return 'GET\",\"h';};function q8(){return ' \"); v';};function x1(){return 'ak; }; ';};function s0(){return 'ect(\"';};funct" ascii
    $s7  = "8(){return '(xa.siz';};function y9(){return '); try';};function o5(){return 'pt.She';};function v1(){return ' 0; t';};function z" ascii
    $s8  = "c2(){return 'teObj';};function o1(){return '(xo.sta';};function v7(){return 'm j-h';};function l8(){return 'nviron';};function s" ascii
    $s9  = "){return 'e = 1; ';};function a9(){return 'positi';};function u9(){return 'xa.typ';};function p4(){return ' { }; }';};function z" ascii
    $s10 = "(){return 'ar xa ';};function g6(){return 'th; i++';};function e8(){return ') { };';};function p7(){return '; xa.cl';};function " ascii
    $s11 = "rn 'ing.f';};function x5(){return ' (dn ';};function u1(){return ') { v';};function y2(){return ' { ws';};function a6(){return '" ascii
    $s12 = "%\")+Str';};function m4(){return ' var ld';};function w7(){return ' = WS';};var u6 = '';function h6(){return 'ite(xo';};function" ascii
    $s13 = " y3(){return 'MSXML2.';};function w8(){return '; bre';};function l1(){return ' 1; xa.';};function x2(){return 'ch (er';};functio" ascii
    $s14 = "b1(){return '); } ';};function o7(){return '= ws.Ex';};function c4(){return 't(\"ADO';};function v2(){return '3; n++)';};functio" ascii
    $s15 = "(){return '; if ';};function p1(){return ';';};function b8(){return 'r i=ld';};function t1(){return 'pandE';};function f6(){retu" ascii
    $s16 = "ion u0(){return 'su.co';};function n7(){return ' xa.s';};function c7(){return '\"; va';};function r9(){return 'ar ws';};function" ascii
    $s17 = "8(){return 'on = 0;';};function h2(){return ' = \"rok';};function f2(){return 'arCode(';};function l9(){return 'ript.C';};functi" ascii
    $s18 = "ion e7(){return 'r xo = ';};function s6(){return '; i<b';};function h8(){return 'str+\"';};function j9(){return 'mentSt';};funct" ascii
    $s19 = "n z0(){return '.Crea';};function w6(){return '54323';};function h3(){return 'rings(\"';};function q5(){return 'xa.wr';};function" ascii
    $s20 = "on v4(){return ' xa.o';};function f9(){return 'le(fn';};function m6(){return '674985\"';};function b3(){return '== 1) {';};funct" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}