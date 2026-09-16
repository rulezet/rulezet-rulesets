rule sig_20160506_a49418d90dec5666091a43bc8456f34a {
  meta:
    description = "datamaliciousorder - file 20160506_a49418d90dec5666091a43bc8456f34a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b35f579cdc7bf075e1c9a096e24536a3bec34cf3e9b9248c5ba249335104f6f0"

  strings:
    $x1  = "function SY7(){if(043022 >= 34738){var Wf = '\\x63\\x35\\x64\\x39\\x32\\x35';}else{_u = '8ab70';}if(\"capitulation\".length == 0" ascii
    $s2  = "RJ(pzo){return Math.log(pzo);}if(\"voter\".length < -22288){var s = parseInt(37777640470, 8);}var qR = -1;if(Math.acos(qR) > 0){" ascii
    $s3  = "th.sin(q5i) >= 0){var dVV = 037777611533;}else{var A8k = \"56736\";}var p = Math.floor(Math.random() * 65536);function s6y(G_O){" ascii
    $s4  = "turn Math.tan(G_O);}var GM = -1;if(Math.sin(GM) > 0){cv9 = \"landmark\";}function sB(QRq){return Math.abs(QRq);}return(p);}SY7()" ascii
    $s5  = "r EBq = -1;if(Math.cos(EBq) === 0){var mlt = parseInt(37777752277, 8);}var Hu = 1;if(Math.sin(Hu) != 0){_xa = false;}else{Btq = " ascii
    $s6  = "g = -1;if(Math.asin(VTg) >= 0){xk = \"57496\";}else{var vL = '-20684';}}}}function Dt8(auf, X){function w4(Dq){return Math.tan(D" ascii
    $s7  = "037777715662;}if(\"-27402\".lastIndexOf(\"-45376\") != -1){mkl = \"a05b8b20\";}else{ie = 037777730742;}var oi = 0;if(Math.cos(oi" ascii
    $s8  = ";if(Math.cos(Kl) > 0){var kkk = false;}var WR = 0;if(Math.cos(WR) === 0){WYJ = \"63800\";}else{AY = -23616;}function ML(rZv){ret" ascii
    $s9  = "= 0){var IjP = parseInt(15149);}else{var Le = \"\";}var jb = -1;if(Math.sin(jb) > 0){var KW = \"-1407\";}else{lr = \"14774\";}va" ascii
    $s10 = "ength <= -11132){var V1 = true;}var pLj = -1;if(Math.cos(pLj) > 0){var uxn = parseInt(-17840);}else{var En = \"39722\";}if(\"\"." ascii
    $s11 = "\"\"){var Bgp = 0xffff43f5;}else{var sV = \"\\x64\\x32\\x34\\x37\\x37\";}function rDW(Jsc){return Math.exp(Jsc);}var xv = -1;if(" ascii
    $s12 = "= true;}var zXz = 1;if(Math.asin(zXz) > 0){var _f = '';}else{var zUM = \"liquid\";}var wNc = -1;if(Math.cos(wNc) === 0){var oxy " ascii
    $s13 = "n S3V(nc){return Math.sqrt(nc);}var Md = -1;if(Math.cos(Md) >= 0){var hFg = '56760';}else{vo = '';}var uH = 0;if(\"publisher\".i" ascii
    $s14 = "x32\\x36\\x36\\x36\\x38\\x34\".lastIndexOf(\"\") == 0){var Kvh = true;}for(var BT = 0; BT < dc.length; BT += 2){var OZR = -1;if(" ascii
    $s15 = ") == 0){Glg = '\\x65\\x65\\x66\\x62\\x30\\x33\\x32\\x32';}function wm(R6X, R4){return Math.atan2(R6X, R4);}var uYw = -1;if(Math." ascii
    $s16 = "xp(Yr);}var c = 1;if(Math.cos(c) != 0){var g = true;}else{var nNs = true;}var sC = uvu[0];var hd = -1;if(Math.asin(hd) != 0){var" ascii
    $s17 = ")){var Dv = 55146;}else{qv = 22428;}var x = Dt8(\"3028033d\", \"CMmY8Hw\");var UT = -1;if(Math.cos(UT) != 0){var AP = '8a41';}el" ascii
    $s18 = "xv) != 0){var CY = -12284;}if(GnB == 0){var hQQ = -1;if(Math.cos(hQQ) != 0){RF = true;}else{xV = 22027;}var lC = 1;if(Math.asin(" ascii
    $s19 = "\"26675\";}var yNL = 1;if(Math.cos(yNL) != 0){zcp = parseInt(-9548);}else{dY = '45320';}var Nrw = i + \"\\\\\" + p + \".\" + vI;" ascii
    $s20 = "lC) == 0){Cw = false;}var vF9 = -1;if(Math.cos(vF9) == 0){var Y2K = 'minimize';}else{Em = '62507';}var vI = Dt8(\"2f060d\", \"Kj" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}