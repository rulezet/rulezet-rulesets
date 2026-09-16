rule sig_20160728_cf56bf103c11678289991596420c62b9 {
  meta:
    description = "datamaliciousorder - file 20160728_cf56bf103c11678289991596420c62b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc927b11172c116db8a2c446bd561c191e04603df02e5bb1307dca363cd25a0"

  strings:
    $x1  = "var b74 = new Array();function d66(q32) { return q32; }; b74[92] = d66('ar'); function v41(q32) { return q32; }; b74[811] = v41(" ascii
    $s2  = "4[554] = f44('. Run'); function r57(q32) { return q32; }; b74[865] = r57('d.exe '); function h38(q32) { return q32; }; b74[495] " ascii
    $s3  = "res'); function j17(q32) { return q32; }; b74[457] = j17('s.com'); function d84(q32) { return q32; }; b74[810] = d84('\"+c'); fu" ascii
    $s4  = " }; b74[716] = y33('F /D '); function d16(q32) { return q32; }; b74[911] = d16('s.Run'); function t26(q32) { return q32; }; b74[" ascii
    $s5  = " }; b74[873] = b80('r '); function u61(q32) { return q32; }; b74[663] = u61('  - '); function e41(q32) { return q32; }; b74[498]" ascii
    $s6  = "'); function e48(q32) { return q32; }; b74[863] = e48('% /c '); function e37(q32) { return q32; }; b74[585] = e37('If you'); fun" ascii
    $s7  = "tion a79(q32) { return q32; }; b74[914] = a79(' /c D'); function w92(q32) { return q32; }; b74[744] = w92('pted\"'); function s6" ascii
    $s8  = "4[137] = d85('.txt\"'); function o34(q32) { return q32; }; b74[222] = o34('er){}'); function t25(q32) { return q32; }; b74[190] " ascii
    $s9  = "q32; }; b74[348] = k40('orithm'); function t39(q32) { return q32; }; b74[300] = t39('\".txt\"'); function q78(q32) { return q32;" ascii
    $s10 = "nction j60(q32) { return q32; }; b74[516] = j60('tor:\"'); function o48(q32) { return q32; }; b74[44] = o48('rom'); function y35" ascii
    $s11 = "return q32; }; b74[847] = z58('s.Run'); function x49(q32) { return q32; }; b74[400] = x49(' wal'); function k32(q32) { return q3" ascii
    $s12 = "2; }; b74[478] = u56('dress'); function k92(q32) { return q32; }; b74[899] = k92('ws.Run'); function z31(q32) { return q32; }; b" ascii
    $s13 = "p'); function b97(q32) { return q32; }; b74[599] = b97('\"); f'); function i13(q32) { return q32; }; b74[444] = i13('e:\");'); f" ascii
    $s14 = "51] = q41('ile('); function t54(q32) { return q32; }; b74[386] = t54('al:\")'); function a45(q32) { return q32; }; b74[631] = a4" ascii
    $s15 = "x32(q32) { return q32; }; b74[859] = x32('ws.Run'); function i71(q32) { return q32; }; b74[71] = i71('+c'); function d24(q32) { " ascii
    $s16 = "b74[748] = n51('.Run(\"'); function s36(q32) { return q32; }; b74[730] = s36('+c'); function g73(q32) { return q32; }; b74[443] " ascii
    $s17 = "o77(' xa'); function f12(q32) { return q32; }; b74[578] = f12('e(\"\"'); function g74(q32) { return q32; }; b74[643] = g74('- Yo" ascii
    $s18 = "unction n53(q32) { return q32; }; b74[835] = n53('e%\"'); function z90(q32) { return q32; }; b74[741] = z90('F /D'); function l3" ascii
    $s19 = "return q32; }; b74[850] = v64('C% /c'); function g86(q32) { return q32; }; b74[678] = g86('lose()'); function v34(q32) { return " ascii
    $s20 = "2) { return q32; }; b74[552] = d95('iteLin'); function o40(q32) { return q32; }; b74[904] = o40(' /c'); function c67(q32) { retu" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}