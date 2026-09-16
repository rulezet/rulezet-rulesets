rule sig_20160724_07408278c94efeac18d24fead45228af {
  meta:
    description = "datamaliciousorder - file 20160724_07408278c94efeac18d24fead45228af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcb750341ddafbfa4f5d1359f7572a7d64632dde1fb92de198a8387352abd806"

  strings:
    $x1  = "var d20 = new Array();function s87(o81,c62) { d20[c62] = o81; }; s87('eLine', 404); function v17(o81,c62) { d20[c62] = o81; }; v" ascii
    $s2  = "', 409); function s56(o81,c62) { d20[c62] = o81; }; s56('r:\"', 519); function x70(o81,c62) { d20[c62] = o81; }; x70('ps.com', 3" ascii
    $s3  = "81,c62) { d20[c62] = o81; }; o36('.dll', 88); function y53(o81,c62) { d20[c62] = o81; }; y53('+c', 844); function v42(o81,c62) {" ascii
    $s4  = "ction v83(o81,c62) { d20[c62] = o81; }; v83('.com', 456); function z97(o81,c62) { d20[c62] = o81; }; z97(' };', 547); function g" ascii
    $s5  = " { d20[c62] = o81; }; e48('e.ru\",', 39); function d44(o81,c62) { d20[c62] = o81; }; d44('.com\"', 42); function v84(o81,c62) { " ascii
    $s6  = "c62] = o81; }; a22('ton', 38); function o64(o81,c62) { d20[c62] = o81; }; o64('  - No', 608); function j58(o81,c62) { d20[c62] =" ascii
    $s7  = "ion x84(o81,c62) { d20[c62] = o81; }; x84(' /y ', 799); function g41(o81,c62) { d20[c62] = o81; }; g41('iteLi', 571); function l" ascii
    $s8  = "; o61('ed usi', 341); function q31(o81,c62) { d20[c62] = o81; }; q31('C% /c ', 927); function o83(o81,c62) { d20[c62] = o81; }; " ascii
    $s9  = " = o81; }; s89('  - Yo', 646); function f76(o81,c62) { d20[c62] = o81; }; f76('n+', 725); function c48(o81,c62) { d20[c62] = o81" ascii
    $s10 = "9('fo.C', 291); function i61(o81,c62) { d20[c62] = o81; }; i61('.l', 148); function u81(o81,c62) { d20[c62] = o81; }; u81(' /c R" ascii
    $s11 = " d20[c62] = o81; }; w56(' /c D', 903); function j42(o81,c62) { d20[c62] = o81; }; j42('ypted ', 652); function m68(o81,c62) { d2" ascii
    $s12 = "[c62] = o81; }; d10('e /t R', 778); function t25(o81,c62) { d20[c62] = o81; }; t25('fp.', 552); function d39(o81,c62) { d20[c62]" ascii
    $s13 = "c62] = o81; }; o90('e(', 256); function b69(o81,c62) { d20[c62] = o81; }; b69('% /c ', 852); function c51(o81,c62) { d20[c62] = " ascii
    $s14 = "1; }; d69(' /c c', 797); function c94(o81,c62) { d20[c62] = o81; }; c94(' BT', 471); function m13(o81,c62) { d20[c62] = o81; }; " ascii
    $s15 = "y{w', 212); function g45(o81,c62) { d20[c62] = o81; }; g45(' /t ', 719); function j68(o81,c62) { d20[c62] = o81; }; j68('=\"', 1" ascii
    $s16 = "] = o81; }; c67('rtant ', 328); function x95(o81,c62) { d20[c62] = o81; }; x95('.txt\")', 136); function q33(o81,c62) { d20[c62]" ascii
    $s17 = "OMSP', 685); function g78(o81,c62) { d20[c62] = o81; }; g78('.R', 924); function h40(o81,c62) { d20[c62] = o81; }; h40('%TEMP', " ascii
    $s18 = " function l90(o81,c62) { d20[c62] = o81; }; l90('.txt\"', 843); function m79(o81,c62) { d20[c62] = o81; }; m79('; };', 933); fun" ascii
    $s19 = "; }; d72('SZ /F', 748); function d63(o81,c62) { d20[c62] = o81; }; d63('p.Wri', 465); function p82(o81,c62) { d20[c62] = o81; };" ascii
    $s20 = "0[c62] = o81; }; z77('ne(\"  ', 662); function u26(o81,c62) { d20[c62] = o81; }; u26('T.txt', 678); function u98(o81,c62) { d20[" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}