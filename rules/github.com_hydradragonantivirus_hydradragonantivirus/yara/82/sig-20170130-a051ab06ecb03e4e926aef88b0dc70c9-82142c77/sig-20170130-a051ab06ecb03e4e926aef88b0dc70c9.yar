rule sig_20170130_a051ab06ecb03e4e926aef88b0dc70c9 {
  meta:
    description = "datamaliciousorder - file 20170130_a051ab06ecb03e4e926aef88b0dc70c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e269e0b04bec52ef4f98f9d5d10a6e27fe176ddd88796d09b9798e00a8b7542d"

  strings:
    $x1  = "var k56 = new Array(); function l12(j84) { return j84; }; k56[405] = l12('\"); ', 42, 59); function d73(i81) { return i81; }; k5" ascii
    $s2  = "45('.com\"', 20, 71, 66); function e54(f47) { return f47; }; k56[292] = e54(' { ', 21); function e44(n78) { return n78; }; k56[7" ascii
    $s3  = "n e79(c86) { return c86; }; k56[520] = e79('wnload', 13, 42, 66); function f25(u74) { return u74; }; k56[464] = f25('ns.com', 99" ascii
    $s4  = "50] = n74('.txt', 8); function r54(v20) { return v20; }; k56[50] = r54('.com\"', 83, 98, 25); function c79(z36) { return z36; };" ascii
    $s5  = " k71(u69) { return u69; }; k56[466] = k71('_bitco', 20, 26); function s69(a94) { return a94; }; k56[805] = s69('py /y ', 87); fu" ascii
    $s6  = "[80] = k46('tS', 89, 64, 100); function d65(s20) { return s20; }; k56[804] = d65(' /c co', 27, 84); function f60(p56) { return p" ascii
    $s7  = ", 36, 58); function k23(q43) { return q43; }; k56[941] = k23('C% /c ', 11); function x87(w63) { return w63; }; k56[191] = x87('r" ascii
    $s8  = "5; }; k56[651] = b12('  ', 32, 37); function h72(d28) { return d28; }; k56[783] = h72('e /t R', 99); function h78(h77) { return " ascii
    $s9  = "d45('ine(\"', 24, 95); function a26(s96) { return s96; }; k56[693] = a26(' /c ', 73, 89); function p38(f70) { return f70; }; k56" ascii
    $s10 = "56[234] = u25('.exe', 98, 85, 53); function h86(s53) { return s53; }; k56[199] = h86('0) { ', 29); function e66(f61) { return f6" ascii
    $s11 = "; }; k56[380] = e64('Wr', 81); function r71(o30) { return o30; }; k56[684] = r71('T.txt)', 27, 2, 36); function a28(q81) { retur" ascii
    $s12 = "k83(j17) { return j17; }; k56[742] = k83('+\".c', 44); function k67(z51) { return z51; }; k56[83] = k67('TEMP%', 57, 22); functi" ascii
    $s13 = "k56[181] = o76('s==', 7, 25, 90); function s97(j70) { return j70; }; k56[854] = s97('s.Run', 83, 49); function s47(f68) { return" ascii
    $s14 = "; function n42(k90) { return k90; }; k56[584] = n42('R:\"); ', 16, 98); function m96(c88) { return c88; }; k56[187] = m96('; ', " ascii
    $s15 = "56[277] = z38(') && ', 38); function i52(l84) { return l84; }; k56[691] = i52('COMSP', 73, 19); function b89(c53) { return c53; " ascii
    $s16 = "(p79) { return p79; }; k56[349] = f57('SA-', 86, 4); function g75(z63) { return z63; }; k56[388] = g75('ual:\"', 6, 78); functio" ascii
    $s17 = " l28; }; k56[447] = y51('re:\")', 17); function r49(r27) { return r27; }; k56[658] = r49('decryp', 21, 5, 30); function z68(b71)" ascii
    $s18 = " function g47(e59) { return e59; }; k56[96] = g47('\"Ms', 65, 29, 94); function p23(p17) { return p17; }; k56[87] = p23('dll\"; " ascii
    $s19 = "); function m43(l79) { return l79; }; k56[764] = m43('EC% /c', 89); function f73(t16) { return t16; }; k56[113] = f73('WScr', 80" ascii
    $s20 = "{ return o35; }; k56[597] = g51('ot pay', 31, 23); function r37(h90) { return h90; }; k56[782] = r37('+\" /v', 89, 8); function " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}