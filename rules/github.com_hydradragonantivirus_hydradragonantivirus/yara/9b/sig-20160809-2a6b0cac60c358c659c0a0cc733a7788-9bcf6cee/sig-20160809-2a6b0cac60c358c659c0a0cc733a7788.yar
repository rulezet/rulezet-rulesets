rule sig_20160809_2a6b0cac60c358c659c0a0cc733a7788 {
  meta:
    description = "datamaliciousorder - file 20160809_2a6b0cac60c358c659c0a0cc733a7788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03edfb78a1797147ec15a13846da710ffc055c8de84b8da4051d996081843cf7"

  strings:
    $x1  = "var d42 = new Array(); function m88(u12,l61) { d42[u12] = l61; }; function m67(x61) { return x61; }; m88(858,m67('t\"+cq,')); fu" ascii
    $s2  = "rr')); function i40(x61) { return x61; }; m88(753,i40('_SZ /F')); function o68(x61) { return x61; }; m88(227,o68('.exe')); funct" ascii
    $s3  = "ion i43(x61) { return x61; }; m88(451,i43('ere:\")')); function z28(x61) { return x61; }; m88(730,z28(' /D \"+')); function w31(" ascii
    $s4  = "1; }; m88(751,t70('e /t ')); function m29(x61) { return x61; }; m88(151,m29('r(')); function n59(x61) { return x61; }; m88(318,n" ascii
    $s5  = "('trin')); function v26(x61) { return x61; }; m88(69,v26('ct(\"WS')); function v25(x61) { return x61; }; m88(741,v25(' /c ')); f" ascii
    $s6  = " return x61; }; m88(810,x36('% /c c')); function h33(x61) { return x61; }; m88(258,h33('e ')); function a78(x61) { return x61; }" ascii
    $s7  = "n n32(x61) { return x61; }; m88(940,n32(' /c DE')); function o54(x61) { return x61; }; m88(196,o54('statu')); function f31(x61) " ascii
    $s8  = "function j43(x61) { return x61; }; m88(916,j43(' /')); function o29(x61) { return x61; }; m88(836,o29('% /c ')); function p68(x6" ascii
    $s9  = "1; }; m88(806,t56('ws.')); function g74(x61) { return x61; }; m88(928,g74('C% /c ')); function r69(x61) { return x61; }; m88(181" ascii
    $s10 = "' /y \"')); function l96(x61) { return x61; }; m88(382,l96('ins).')); function k70(x61) { return x61; }; m88(194,k70('d(); i'));" ascii
    $s11 = "(x61) { return x61; }; m88(674,o48('  - Y')); function b58(x61) { return x61; }; m88(470,b58('itc')); function i39(x61) { return" ascii
    $s12 = "}; m88(887,r72('\".txt\"')); function m71(x61) { return x61; }; m88(542,m71('.W')); function b76(x61) { return x61; }; m88(233,b" ascii
    $s13 = "function b51(x61) { return x61; }; m88(120,b51('eO')); function t35(x61) { return x61; }; m88(815,t35('.txt\"')); function r94(x" ascii
    $s14 = "eturn x61; }; m88(96,k94('TEMP')); function d18(x61) { return x61; }; m88(311,d18('rue); ')); function c15(x61) { return x61; };" ascii
    $s15 = "nction q61(x61) { return x61; }; m88(58,q61('itz3f')); function h92(x61) { return x61; }; m88(81,h92('TEMP')); function w55(x61)" ascii
    $s16 = "4,s32('(\"%C')); function a48(x61) { return x61; }; m88(681,a48(' you')); function o27(x61) { return x61; }; m88(732,o27('\".txt" ascii
    $s17 = "s69('; ')); function v22(x61) { return x61; }; m88(843,v22('.txt\"')); function s26(x61) { return x61; }; m88(680,s26('on')); fu" ascii
    $s18 = "85('f the ')); function z53(x61) { return x61; }; m88(241,z53('f(n==3')); function y47(x61) { return x61; }; m88(393,y47('l:\"')" ascii
    $s19 = "; function b67(x61) { return x61; }; m88(936,b67('s.Run(')); function s67(x61) { return x61; }; m88(124,s67('.Str')); function v" ascii
    $s20 = " return x61; }; m88(11,y29('r ld')); function v63(x61) { return x61; }; m88(412,v63('e:\")')); function o59(x61) { return x61; }" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}