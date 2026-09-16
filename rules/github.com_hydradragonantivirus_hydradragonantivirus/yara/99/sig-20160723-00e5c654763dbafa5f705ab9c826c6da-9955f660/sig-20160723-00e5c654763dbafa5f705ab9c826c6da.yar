rule sig_20160723_00e5c654763dbafa5f705ab9c826c6da {
  meta:
    description = "datamaliciousorder - file 20160723_00e5c654763dbafa5f705ab9c826c6da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e278df44bf03816ae38a373cd08a82ea503648dba2f1df2e352710391317076d"

  strings:
    $x1  = "var i77 = new Array();function m74(l87,h93) { i77[h93] = l87; }; m74('i=ld;i', 151); function c23(l87,h93) { i77[h93] = l87; }; " ascii
    $s2  = "5(l87,h93) { i77[h93] = l87; }; g45('- If', 602); function e26(l87,h93) { i77[h93] = l87; }; e26('.Run(\"', 766); function j90(l" ascii
    $s3  = "93] = l87; }; v77('ual:\")', 393); function r29(l87,h93) { i77[h93] = l87; }; r29('a.sav', 234); function n25(l87,h93) { i77[h93" ascii
    $s4  = "19(l87,h93) { i77[h93] = l87; }; t19('% /c ', 699); function p60(l87,h93) { i77[h93] = l87; }; p60('tStri', 75); function w43(l8" ascii
    $s5  = "; function a35(l87,h93) { i77[h93] = l87; }; a35('fn+\".', 255); function d84(l87,h93) { i77[h93] = l87; }; d84(' /c co', 812); " ascii
    $s6  = "', 853); function k37(l87,h93) { i77[h93] = l87; }; k37('ipting', 128); function u68(l87,h93) { i77[h93] = l87; }; u68(' - ', 62" ascii
    $s7  = "function v63(l87,h93) { i77[h93] = l87; }; v63('+cs', 782); function v70(l87,h93) { i77[h93] = l87; }; v70(' - ', 677); function" ascii
    $s8  = "(l87,h93) { i77[h93] = l87; }; p99(' /c ', 917); function c77(l87,h93) { i77[h93] = l87; }; c77('pa', 879); function w18(l87,h93" ascii
    $s9  = ") { i77[h93] = l87; }; l23(' - I', 634); function y95(l87,h93) { i77[h93] = l87; }; y95('addr', 490); function y39(l87,h93) { i7" ascii
    $s10 = "ow t', 390); function s77(l87,h93) { i77[h93] = l87; }; s77('+\" /t ', 730); function y17(l87,h93) { i77[h93] = l87; }; y17('p.W" ascii
    $s11 = " function b67(l87,h93) { i77[h93] = l87; }; b67('decr', 573); function c21(l87,h93) { i77[h93] = l87; }; c21('\".txt\"', 818); f" ascii
    $s12 = "d92('d.exe ', 880); function h57(l87,h93) { i77[h93] = l87; }; h57('q+', 786); function p46(l87,h93) { i77[h93] = l87; }; p46('/" ascii
    $s13 = "93] = l87; }; u42('PT.txt', 690); function y87(l87,h93) { i77[h93] = l87; }; y87('sh, ', 446); function i39(l87,h93) { i77[h93] " ascii
    $s14 = " = l87; }; k34('.txt\"', 304); function z30(l87,h93) { i77[h93] = l87; }; z30('REG_SZ', 731); function e69(l87,h93) { i77[h93] =" ascii
    $s15 = "7[h93] = l87; }; v82('.exe\"', 224); function d78(l87,h93) { i77[h93] = l87; }; d78(' BTC', 443); function l68(l87,h93) { i77[h9" ascii
    $s16 = ") { i77[h93] = l87; }; m99('p.Wri', 569); function d38(l87,h93) { i77[h93] = l87; }; d38('\".exe', 215); function k71(l87,h93) {" ascii
    $s17 = "\"+c', 867); function p26(l87,h93) { i77[h93] = l87; }; p26('rypted', 775); function l36(l87,h93) { i77[h93] = l87; }; l36('e:\"" ascii
    $s18 = "87,h93) { i77[h93] = l87; }; q63('EG ', 745); function d79(l87,h93) { i77[h93] = l87; }; d79('.Run', 695); function n20(l87,h93)" ascii
    $s19 = " i77[h93] = l87; }; g31('ch', 271); function r44(l87,h93) { i77[h93] = l87; }; r44('ess:\"', 491); function l57(l87,h93) { i77[h" ascii
    $s20 = "87; }; x25('un', 170); function b72(l87,h93) { i77[h93] = l87; }; b72('re:\");', 451); function b78(l87,h93) { i77[h93] = l87; }" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}