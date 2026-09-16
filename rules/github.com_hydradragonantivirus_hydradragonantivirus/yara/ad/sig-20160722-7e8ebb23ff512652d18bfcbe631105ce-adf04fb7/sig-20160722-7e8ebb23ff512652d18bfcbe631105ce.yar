rule sig_20160722_7e8ebb23ff512652d18bfcbe631105ce {
  meta:
    description = "datamaliciousorder - file 20160722_7e8ebb23ff512652d18bfcbe631105ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "660cc8793e265bc259d440d9581d840460adbb951c76b856882936a3c260734d"

  strings:
    $x1  = "var m14 = new Array();function v51(i45,a90) { m14[a90] = i45; }; v51('+\".tx', 822); function n30(i45,a90) { m14[a90] = i45; }; " ascii
    $s2  = "ction k45(i45,a90) { m14[a90] = i45; }; k45('% /c ', 919); function c63(i45,a90) { m14[a90] = i45; }; c63('YOU', 582); function " ascii
    $s3  = ". Op', 491); function h80(i45,a90) { m14[a90] = i45; }; h80(' - If ', 575); function f16(i45,a90) { m14[a90] = i45; }; f16('=3){" ascii
    $s4  = " }; z19('(\"', 400); function l43(i45,a90) { m14[a90] = i45; }; l43('ve /t ', 732); function i82(i45,a90) { m14[a90] = i45; }; i" ascii
    $s5  = "45; }; n19('(fn', 226); function i28(i45,a90) { m14[a90] = i45; }; i28(' /t R', 766); function p60(i45,a90) { m14[a90] = i45; };" ascii
    $s6  = "69); function g41(i45,a90) { m14[a90] = i45; }; g41(' (', 663); function h48(i45,a90) { m14[a90] = i45; }; h48('  - Y', 635); fu" ascii
    $s7  = "e%\"', 828); function g83(i45,a90) { m14[a90] = i45; }; g83('  - Yo', 654); function r42(i45,a90) { m14[a90] = i45; }; r42('ne(" ascii
    $s8  = "(i45,a90) { m14[a90] = i45; }; y40('% /c ', 893); function g58(i45,a90) { m14[a90] = i45; }; g58(' w', 901); function m95(i45,a9" ascii
    $s9  = "14[a90] = i45; }; g31('tiv', 624); function b63(i45,a90) { m14[a90] = i45; }; b63('  - N', 596); function q65(i45,a90) { m14[a90" ascii
    $s10 = "2('r:\");', 506); function p63(i45,a90) { m14[a90] = i45; }; p63('r ws', 54); function s95(i45,a90) { m14[a90] = i45; }; s95('en" ascii
    $s11 = "m14[a90] = i45; }; m41('+\"DEC', 833); function i64(i45,a90) { m14[a90] = i45; }; i64('.Run(\"', 717); function g88(i45,a90) { m" ascii
    $s12 = "ction w52(i45,a90) { m14[a90] = i45; }; w52('l:\"', 377); function b37(i45,a90) { m14[a90] = i45; }; b37('ar', 5); function v85(" ascii
    $s13 = "[a90] = i45; }; g15('e:\"', 391); function u22(i45,a90) { m14[a90] = i45; }; u22('teO', 58); function a63(i45,a90) { m14[a90] = " ascii
    $s14 = "[a90] = i45; }; f76('+\".ex', 846); function l87(i45,a90) { m14[a90] = i45; }; l87(' /c', 844); function d97(i45,a90) { m14[a90]" ascii
    $s15 = "m14[a90] = i45; }; y70('F /D', 735); function d78(i45,a90) { m14[a90] = i45; }; d78('n+', 211); function k83(i45,a90) { m14[a90]" ascii
    $s16 = "(i45,a90) { m14[a90] = i45; }; f50('urre', 694); function d79(i45,a90) { m14[a90] = i45; }; d79('% /c', 746); function n20(i45,a" ascii
    $s17 = "7('- It', 612); function x68(i45,a90) { m14[a90] = i45; }; x68('cq,0', 899); function c13(i45,a90) { m14[a90] = i45; }; c13('\"R" ascii
    $s18 = "10(i45,a90) { m14[a90] = i45; }; k10('\" /t', 706); function h78(i45,a90) { m14[a90] = i45; }; h78('0;i<10', 879); function m93(" ascii
    $s19 = "0] = i45; }; c17('  ', 653); function k91(i45,a90) { m14[a90] = i45; }; k91('SZ /F ', 708); function n19(i45,a90) { m14[a90] = i" ascii
    $s20 = " = i45; }; k83('com\",\"', 45); function c89(i45,a90) { m14[a90] = i45; }; c89('()', 670); function d75(i45,a90) { m14[a90] = i4" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}