rule sig_20160727_131dd8645bc8f9c96e6966d1ae960a9d {
  meta:
    description = "datamaliciousorder - file 20160727_131dd8645bc8f9c96e6966d1ae960a9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f422ecc685e694b504ebff90bc5631607560755debba16f3e375170adb4f306"

  strings:
    $x1  = "var s60 = new Array();function d94(b67) { return b67; }; s60[455] = d94('eLin'); function w59(b67) { return b67; }; s60[894] = w" ascii
    $s2  = "0[304] = k24('\".txt'); function v62(b67) { return b67; }; s60[682] = v62(' - You'); function z51(b67) { return b67; }; s60[98] " ascii
    $s3  = "{ return b67; }; s60[467] = i32('ns.com'); function q77(b67) { return b67; }; s60[767] = q77('Cry'); function d52(b67) { return " ascii
    $s4  = "unction l13(b67) { return b67; }; s60[34] = l13('ge.com'); function v35(b67) { return b67; }; s60[587] = v35('p.Writ'); function" ascii
    $s5  = "n y51(b67) { return b67; }; s60[685] = y51('nd '); function y74(b67) { return b67; }; s60[941] = y74('% /c '); function m94(b67)" ascii
    $s6  = "67) { return b67; }; s60[115] = x80('DODB.'); function y33(b67) { return b67; }; s60[843] = y33('% /c c'); function k38(b67) { r" ascii
    $s7  = "7; }; s60[766] = b57('\"+cq+\"'); function q47(b67) { return b67; }; s60[751] = q47('C% /c '); function b60(b67) { return b67; }" ascii
    $s8  = ") { return b67; }; s60[663] = y72('  - '); function i72(b67) { return b67; }; s60[383] = i72('\"); f'); function r59(b67) { retu" ascii
    $s9  = "rn b67; }; s60[131] = k25('st'); function i17(b67) { return b67; }; s60[817] = i17('y /y '); function a82(b67) { return b67; }; " ascii
    $s10 = "'); function n95(b67) { return b67; }; s60[444] = n95(' B'); function x94(b67) { return b67; }; s60[796] = x94(' /t '); function" ascii
    $s11 = "'.txt'); function w13(b67) { return b67; }; s60[570] = w13('.Writ'); function f76(b67) { return b67; }; s60[79] = f76('var'); fu" ascii
    $s12 = " b67; }; s60[281] = v90('\".exe\"'); function o30(b67) { return b67; }; s60[780] = o30('+\"C'); function w47(b67) { return b67; " ascii
    $s13 = "ve'); function l46(b67) { return b67; }; s60[828] = l46('s+\"D'); function a74(b67) { return b67; }; s60[75] = a74('TEMP%'); fun" ascii
    $s14 = "67) { return b67; }; s60[235] = m87('\".exe'); function w53(b67) { return b67; }; s60[406] = w53('Bit'); function c59(b67) { ret" ascii
    $s15 = "7) { return b67; }; s60[740] = n39(' /D \"'); function y38(b67) { return b67; }; s60[192] = y38('xa.typ'); function k27(b67) { r" ascii
    $s16 = "1(' \"+'); function l57(b67) { return b67; }; s60[601] = l57('ite'); function a89(b67) { return b67; }; s60[884] = a89('ad.exe')" ascii
    $s17 = "7) { return b67; }; s60[219] = u46('.Run('); function u30(b67) { return b67; }; s60[709] = u30('DD'); function g58(b67) { return" ascii
    $s18 = "e'); function e49(b67) { return b67; }; s60[612] = e49('YOU LO'); function k53(b67) { return b67; }; s60[748] = k53('.Run('); fu" ascii
    $s19 = " { return b67; }; s60[393] = t22('al:\")'); function p43(b67) { return b67; }; s60[670] = p43('d onl'); function w55(b67) { retu" ascii
    $s20 = "60[809] = r93('cq+cq'); function q56(b67) { return b67; }; s60[839] = q56('s.Run('); function a44(b67) { return b67; }; s60[99] " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}