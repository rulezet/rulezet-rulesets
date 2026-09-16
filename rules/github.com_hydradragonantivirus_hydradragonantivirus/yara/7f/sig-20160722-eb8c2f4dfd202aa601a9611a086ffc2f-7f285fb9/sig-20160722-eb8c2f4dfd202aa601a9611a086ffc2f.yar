rule sig_20160722_eb8c2f4dfd202aa601a9611a086ffc2f {
  meta:
    description = "datamaliciousorder - file 20160722_eb8c2f4dfd202aa601a9611a086ffc2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63b8175e8ab3de1c1e527f73988bb8288a4458680fb4fd65ab1adbd0330fc13f"

  strings:
    $x1  = "var z86 = new Array();function g66(x93,y59) { z86[y59] = x93; }; g66('); fp', 606); function l30(x93,y59) { z86[y59] = x93; }; l" ascii
    $s2  = "n t54(x93,y59) { z86[y59] = x93; }; t54('2);', 248); function e86(x93,y59) { z86[y59] = x93; }; e86('.dll', 92); function f57(x9" ascii
    $s3  = " { z86[y59] = x93; }; f53(' /c DE', 927); function r56(x93,y59) { z86[y59] = x93; }; r56('COMSP', 867); function k30(x93,y59) { " ascii
    $s4  = "('.com/', 461); function m87(x93,y59) { z86[y59] = x93; }; m87('RE', 748); function u70(x93,y59) { z86[y59] = x93; }; u70('op\"+" ascii
    $s5  = "93; }; z76(' - Nob', 611); function c97(x93,y59) { z86[y59] = x93; }; c97('e ', 372); function h66(x93,y59) { z86[y59] = x93; };" ascii
    $s6  = "nction l73(x93,y59) { z86[y59] = x93; }; l73(' /t ', 722); function n51(x93,y59) { z86[y59] = x93; }; n51('pdate', 640); functio" ascii
    $s7  = " f33(x93,y59) { z86[y59] = x93; }; f33('% /c R', 737); function n50(x93,y59) { z86[y59] = x93; }; n50('aveToF', 212); function w" ascii
    $s8  = "1('.cn\",\"', 46); function l56(x93,y59) { z86[y59] = x93; }; l56(' /c DE', 940); function h95(x93,y59) { z86[y59] = x93; }; h95" ascii
    $s9  = "604); function i52(x93,y59) { z86[y59] = x93; }; i52('y /y ', 805); function u77(x93,y59) { z86[y59] = x93; }; u77('ode(92', 25)" ascii
    $s10 = ", 158); function q55(x93,y59) { z86[y59] = x93; }; q55('% /c ', 803); function q10(x93,y59) { z86[y59] = x93; }; q10('de', 561);" ascii
    $s11 = "{ z86[y59] = x93; }; g91('REG AD', 696); function b33(x93,y59) { z86[y59] = x93; }; b33('.exe \"', 873); function a42(x93,y59) {" ascii
    $s12 = "2('\".txt', 727); function r64(x93,y59) { z86[y59] = x93; }; r64('cq', 754); function v23(x93,y59) { z86[y59] = x93; }; v23('TP" ascii
    $s13 = "59] = x93; }; y47('\"+cq', 877); function w72(x93,y59) { z86[y59] = x93; }; w72('.exe', 859); function b40(x93,y59) { z86[y59] =" ascii
    $s14 = "3,y59) { z86[y59] = x93; }; h79('pt.Cr', 59); function p40(x93,y59) { z86[y59] = x93; }; p40('\".exe\"', 281); function y97(x93," ascii
    $s15 = "x93; }; b40('.exe\"', 932); function t51(x93,y59) { z86[y59] = x93; }; t51('(\"', 415); function x34(x93,y59) { z86[y59] = x93; " ascii
    $s16 = " function z93(x93,y59) { z86[y59] = x93; }; z93('ws.Run', 692); function z89(x93,y59) { z86[y59] = x93; }; z89('ateT', 883); fun" ascii
    $s17 = "9] = x93; }; n79('HKC', 765); function i96(x93,y59) { z86[y59] = x93; }; i96('or:\")', 521); function z76(x93,y59) { z86[y59] = " ascii
    $s18 = ", 887); function a23(x93,y59) { z86[y59] = x93; }; a23('here:\"', 405); function m98(x93,y59) { z86[y59] = x93; }; m98('File(', " ascii
    $s19 = "ad', 901); function r83(x93,y59) { z86[y59] = x93; }; r83('.Run(', 825); function i63(x93,y59) { z86[y59] = x93; }; i63(']+\"', " ascii
    $s20 = "nction f49(x93,y59) { z86[y59] = x93; }; f49('s.Run', 733); function b29(x93,y59) { z86[y59] = x93; }; b29('/cou', 168); functio" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}