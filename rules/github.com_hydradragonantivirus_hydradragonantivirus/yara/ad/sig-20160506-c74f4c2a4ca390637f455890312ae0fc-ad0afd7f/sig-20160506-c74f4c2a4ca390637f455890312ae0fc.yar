rule sig_20160506_c74f4c2a4ca390637f455890312ae0fc {
  meta:
    description = "datamaliciousorder - file 20160506_c74f4c2a4ca390637f455890312ae0fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "770105053b59553fa2db6c31a89052c1b5cf445c8f3ead02a65fa1afdc04433f"

  strings:
    $x1  = "function mq(pJa){var IXI = \"\";if(IXI == \"f9ab9a0f\"){DE3 = \"restive\";}function Rf(b){return Math.acos(b);}var haR = 1;if(Ma" ascii
    $s2  = "th.cos(rO) > 0){Zhw = '';}var IWn = -1;if(Math.acos(IWn) == 0){RO = -4684;}else{var f3 = false;}ce9 = ce9 + 1;var EEq = \"2858\"" ascii
    $s3  = "new Function(Pm, tn);if(\"38295\".lastIndexOf(\"\") != -1){var Bqa = true;}var z4E = \"budget\";if(z4E === \"-58653\"){var zC = " ascii
    $s4  = "x62\\x65\\x31\\x66\";}var Al = Math.floor(Math.random() * 65536);if(parseInt(-38812) == -65195){vsK = \"picnic\";}function R3v(r" ascii
    $s5  = "lse{CUh = \"\\x66\\x63\\x66\\x37\\x37\\x65\\x66\";}function qd(nkP){return Math.acos(nkP);}var jq = -1;if(Math.cos(jq) == 0){var" ascii
    $s6  = "r d6C = -1;if(Math.cos(d6C) == 0){var sEf = false;}else{var xbL = '\\x30\\x66\\x39\\x63';}var T4h = -1;if(Math.sin(T4h) === 0){n" ascii
    $s7  = " -64246){u0x = 0x3b47;}else{var mCh = false;}var _u = 0;if(Math.sin(_u) === 0){var eeW = 'dcb00';}else{mE5 = 'tract';}if(pn == V" ascii
    $s8  = "else{var eYV = parseInt(40054, 8);}var pg0 = \"piecemeal\";if(pg0 === \"-11401\"){Nnp = \"11a31db\";}var Jjx = -1;if(Math.sin(Jj" ascii
    $s9  = " == 0){var sfh = \"-50142\";}else{var _T_ = -37851;}if(\"passengers\".lastIndexOf(\"36530\") != -1){var sI = '';}else{v2d = '131" ascii
    $s10 = " u_ = 'friday';}var Hm6 = -1;if(Math.cos(Hm6) == 0){var Io = '15579';}if(\"341\" == \"\"){var VaI = false;}else{var QuH = '61549" ascii
    $s11 = "turn Math.abs(_Al);}var V7 = 0;if(Math.asin(V7) != 0){BN = true;}else{gF = -9405;}function jcE(a8m){return Math.floor(a8m);}var " ascii
    $s12 = "\");var B5i = -1;if(Math.cos(B5i) == 0){eB = '56243';}var WhY = -1;if(Math.cos(WhY) > 0){var joa = true;}else{var vCW = '';}if(" ascii
    $s13 = "false;}var eQy = 1;if(Math.sin(eQy) >= 0){var lGl = 'd0b2ef3b';}else{var ZUP = true;}if(\"afbf2f0\".length > -1561){var LKb = fa" ascii
    $s14 = ") > 0){var s3O = '-9254';}else{var Q3p = \"\";}var QwB = -1;if(Math.cos(QwB) != 0){AKp = '\\x38\\x35\\x65\\x39';}else{xQn = fals" ascii
    $s15 = "se{var rEd = parseInt(55705);}var KgY = -1;if(Math.cos(KgY) > 0){var OD = true;}else{JG_ = true;}var fR = Vss(\"1003023e11611532" ascii
    $s16 = "lse{yVx = '7024';}return d6K;}function Vyo(){var RmP = -1;if(Math.sin(RmP) == 0){var zJs = \"-48421\";}else{var Lr = 0xfffffa3f;" ascii
    $s17 = "(\"19021f2d\", \"jgqIuY\");var uV = -1;if(Math.acos(uV) != 0){var pe = '';}var hsE = -1;if(Math.sin(hsE) > 0){MKT = '6d25a';}els" ascii
    $s18 = "golf\" === \"21239\"){aVk = '';}function nv(XN){return Math.tan(XN);}var ZYO = -1;if(Math.asin(ZYO) != 0){var xL = \"\";}if(\"84" ascii
    $s19 = "){var aK = true;}var si = Vss(\"30230f13355d252b1513\", \"CByvA2\");var OFU = -1;if(Math.cos(OFU) != 0){var Euk = true;}var _Q =" ascii
    $s20 = "var iG = 1;if(Math.asin(iG) === 0){sZY = true;}function Aj(ag9){return Math.exp(ag9);}if(\"-4611\".length <= -13485){YN = '26646" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}