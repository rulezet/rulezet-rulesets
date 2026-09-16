rule sig_20160807_6aa3e73d33a1896f71824d85c3841765 {
  meta:
    description = "datamaliciousorder - file 20160807_6aa3e73d33a1896f71824d85c3841765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fd3b1e06a24b7daae7443f659854146d90559e3818ed639cf6d2d694887f0f"

  strings:
    $x1  = "var p26 = new Array(); function f85(g55,w27) { p26[g55] = w27; }; function w25(h51) { return h51; }; f85(763,w25('\"s')); functi" ascii
    $s2  = "; }; f85(831,e96('.txt\"')); function q63(h51) { return h51; }; f85(727,q63('% /c ')); function j86(h51) { return h51; }; f85(55" ascii
    $s3  = "89,x79('%TEMP%')); function c81(h51) { return h51; }; f85(819,c81('q,0,0')); function k59(h51) { return h51; }; f85(406,k59('e(" ascii
    $s4  = " h51; }; f85(459,h31('.com/b')); function a16(h51) { return h51; }; f85(42,a16('\"xn-')); function p25(h51) { return h51; }; f85" ascii
    $s5  = ".com\",')); function i14(h51) { return h51; }; f85(131,i14('ec')); function p46(h51) { return h51; }; f85(833,p46('q+')); functi" ascii
    $s6  = ")); function h49(h51) { return h51; }; f85(602,h49(' - Nob')); function t40(h51) { return h51; }; f85(879,t40('o.')); function y" ascii
    $s7  = "on i94(h51) { return h51; }; f85(825,i94('C% /c ')); function s49(h51) { return h51; }; f85(171,s49('\"&rnd')); function z58(h51" ascii
    $s8  = "8(h51) { return h51; }; f85(927,p58(' /c D')); function z74(h51) { return h51; }; f85(676,z74('; fp.')); function g49(h51) { ret" ascii
    $s9  = "(h51) { return h51; }; f85(794,f11(' /c ')); function d80(h51) { return h51; }; f85(804,d80('+\"%Ap')); function g27(h51) { retu" ascii
    $s10 = "n')); function r54(h51) { return h51; }; f85(682,r54('% /c R')); function x78(h51) { return h51; }; f85(434,x78('y ')); function" ascii
    $s11 = ")); function e92(h51) { return h51; }; f85(868,e92('% /c n')); function e11(h51) { return h51; }; f85(451,e11('iteL')); function" ascii
    $s12 = "56('\".exe')); function h76(h51) { return h51; }; f85(715,h76('+c')); function c58(h51) { return h51; }; f85(821,c58(' ws.')); f" ascii
    $s13 = "p51(h51) { return h51; }; f85(138,p51('.txt\"')); function r46(h51) { return h51; }; f85(265,r46('};')); function p38(h51) { ret" ascii
    $s14 = "'ea')); function n61(h51) { return h51; }; f85(919,n61('.exe\"')); function k35(h51) { return h51; }; f85(583,k35('  ')); functi" ascii
    $s15 = "return h51; }; f85(68,w34('r fn=w')); function e47(h51) { return h51; }; f85(75,e47('TEMP%\"')); function z50(h51) { return h51;" ascii
    $s16 = "function r47(h51) { return h51; }; f85(233,r47('.exe\",')); function s63(h51) { return h51; }; f85(413,s63('  ')); function r36(" ascii
    $s17 = "768,j27('s+\"com')); function v39(h51) { return h51; }; f85(446,v39('p.Wri')); function u93(h51) { return h51; }; f85(503,u93(' " ascii
    $s18 = "on c32(h51) { return h51; }; f85(672,c32('op')); function q27(h51) { return h51; }; f85(402,q27('here:\"')); function z51(h51) {" ascii
    $s19 = "return h51; }; f85(480,f29('ss:\")')); function q96(h51) { return h51; }; f85(836,q96('\"%Use')); function r50(h51) { return h51" ascii
    $s20 = "51; }; f85(921,b97('0); ws')); function l43(h51) { return h51; }; f85(384,l43('al:\")')); function c49(h51) { return h51; }; f85" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}