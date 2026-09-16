rule sig_20160721_ce715ff24c17092b30e060bdeefc9999 {
  meta:
    description = "datamaliciousorder - file 20160721_ce715ff24c17092b30e060bdeefc9999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d320c2b9c2a4f0d17b2c4a58fc31e20169964529b4a202213da27fa1e25c1937"

  strings:
    $x1  = "var l71 = new Array();function f37(f85,a62) { l71[a62] = f85; }; f37('% /', 909); function o28(f85,a62) { l71[a62] = f85; }; o28" ascii
    $s2  = "tion z52(f85,a62) { l71[a62] = f85; }; z52('ch.com', 52); function v24(f85,a62) { l71[a62] = f85; }; v24('.s', 242); function a2" ascii
    $s3  = "r l', 12); function g28(f85,a62) { l71[a62] = f85; }; g28('.com/', 472); function o70(f85,a62) { l71[a62] = f85; }; o70('te', 13" ascii
    $s4  = " l71[a62] = f85; }; a76('\"); fp', 422); function x40(f85,a62) { l71[a62] = f85; }; x40('  - Y', 668); function s94(f85,a62) { l" ascii
    $s5  = "ion z80(f85,a62) { l71[a62] = f85; }; z80('C% /c ', 827); function g24(f85,a62) { l71[a62] = f85; }; g24('o r', 572); function p" ascii
    $s6  = "2) { l71[a62] = f85; }; r38('  - I', 598); function s65(f85,a62) { l71[a62] = f85; }; s65('fp', 896); function z61(f85,a62) { l7" ascii
    $s7  = "(f85,a62) { l71[a62] = f85; }; x27('% /c ', 853); function z10(f85,a62) { l71[a62] = f85; }; z10('nt', 708); function x60(f85,a6" ascii
    $s8  = "2) { l71[a62] = f85; }; x60(' - You', 649); function h54(f85,a62) { l71[a62] = f85; }; h54('i<1000', 893); function v73(f85,a62)" ascii
    $s9  = "2) { l71[a62] = f85; }; v97('R FILE', 610); function r50(f85,a62) { l71[a62] = f85; }; r50(' /c D', 935); function u23(f85,a62) " ascii
    $s10 = "44(f85,a62) { l71[a62] = f85; }; p44('is Bi', 488); function t50(f85,a62) { l71[a62] = f85; }; t50(' /t R', 745); function y23(f" ascii
    $s11 = "71[a62] = f85; }; j39(' /c R', 690); function u37(f85,a62) { l71[a62] = f85; }; u37('for(va', 890); function e78(f85,a62) { l71[" ascii
    $s12 = "63); function s14(f85,a62) { l71[a62] = f85; }; s14('.exe\",', 233); function j41(f85,a62) { l71[a62] = f85; }; j41('rre', 707);" ascii
    $s13 = "ke pa', 659); function t33(f85,a62) { l71[a62] = f85; }; t33('TEMP%\"', 80); function p11(f85,a62) { l71[a62] = f85; }; p11('Cod" ascii
    $s14 = "f85,a62) { l71[a62] = f85; }; p85('HKCR\"+', 739); function y15(f85,a62) { l71[a62] = f85; }; y15('.exe', 927); function v71(f85" ascii
    $s15 = "'.txt\"+', 847); function v41(f85,a62) { l71[a62] = f85; }; v41('eLin', 899); function a61(f85,a62) { l71[a62] = f85; }; a61('(n" ascii
    $s16 = " = f85; }; y29('.txt', 818); function w57(f85,a62) { l71[a62] = f85; }; w57('G_SZ /', 722); function n82(f85,a62) { l71[a62] = f" ascii
    $s17 = "5; }; u96(',0', 940); function h53(f85,a62) { l71[a62] = f85; }; h53('.txt).', 681); function o44(f85,a62) { l71[a62] = f85; }; " ascii
    $s18 = "e', 561); function e32(f85,a62) { l71[a62] = f85; }; e32('cs+\"Cr', 764); function p31(f85,a62) { l71[a62] = f85; }; p31('.Run'," ascii
    $s19 = "ction g18(f85,a62) { l71[a62] = f85; }; g18('s:\"', 492); function v62(f85,a62) { l71[a62] = f85; }; v62('CRYPT', 680); function" ascii
    $s20 = "f85; }; t60('+\"C', 750); function x78(f85,a62) { l71[a62] = f85; }; x78('r:\")', 531); function a67(f85,a62) { l71[a62] = f85; " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}