rule sig_20160506_3bba9564b7deaa7b59ac61356f0408da {
  meta:
    description = "datamaliciousorder - file 20160506_3bba9564b7deaa7b59ac61356f0408da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00401116d66df0d8515c101ab0009878a795bae93b6f7a3b5d702bb26840de35"

  strings:
    $x1  = "function R(V0L){if(\"-9531\".lastIndexOf(\"32626\") == -1){var iL = -19566;}else{Z8q = parseInt(51028);}var WyR = 1;if(Math.asin" ascii
    $s2  = "h == -21937){var ma_ = parseInt(2681);}else{CC = 0xfffffc2b;}if(\"targets\" != \"handjobs\"){var ZyF = parseInt(-31559);}else{gn" ascii
    $s3  = "r S = 0;if(Math.acos(S) > 0){OMx = 56116;}else{uB = \"curative\";}function Pqk(Vi){return Math.log(Vi);}ji7 = 0;}}if(\"-24371\"." ascii
    $s4  = "h.log(Ec);}var mcU = \"\";var ly = \"\";if(mcU === ly){var Lxv = '-11728';}else{puW = '-15547';}for(WEE = 0; WEE < P.length; WEE" ascii
    $s5  = "95);}var BpU = mNM(\"01162808\", \"uoXmihR\");function lW(WhY){return Math.log(WhY);}var fE = \"lima\";var HJ = \"-21242\";if(fE" ascii
    $s6  = "rn Math.log(as);}var xs5 = 0;if(Math.acos(xs5) != 0){sgA = false;}else{var nH = \"\\x64\\x66\\x63\\x65\\x62\";}var ZA = \"32445" ascii
    $s7  = "(etl){return Math.log(etl);}if(\"tex\" != \"-19070\"){var H8p = \"\\x31\\x33\\x31\\x36\\x64\\x35\\x64\\x34\";}else{Iu = \"\";}if" ascii
    $s8  = " = 37366;}else{var RCs = 'ea4a';}function Wo0(Cx){return Math.log(Cx);}var iI = \"-61928\";if(iI === \"28154\"){Rx = \"af396\";}" ascii
    $s9  = "ath.sin(CsH) != 0){abW = -11770;}else{var P8p = true;}var g = mNM(\"020821571a4f1c171e2b5215\", \"clN3xao\");var bn = 0;if(Math." ascii
    $s10 = "0);}if(\"\" === \"\"){var ie = true;}var doh = 0;if(Math.cos(doh) != 0){vTh = 'analog';}else{IW = \"-31829\";}function DO(ZzM){r" ascii
    $s11 = "x = \"\";}if(0112527 <= -57822){var jyU = \"\";}xmH[Ekn](vmh, 1, 0);break;}var nI = -1;if(Math.sin(nI) != 0){var Mt_ = parseInt(" ascii
    $s12 = "var mb = -1;if(Math.sin(mb) != 0){var Rzl = -54479;}if(39531 == parseInt(-16016)){var sEf = true;}else{var xbL = '57193';}var sm" ascii
    $s13 = "r Btq = true;}else{lt = true;}var kd = -1;if(Math.cos(kd) == 0){var d_ = \"\\x66\\x38\\x32\\x31\\x38\\x63\";}else{var i4 = true;" ascii
    $s14 = "r tj = -1;if(Math.cos(tj) == 0){vd = false;}if(\"\".length >= parseInt(72724, 8)){var _qT = \"2240\";}var bm = 1;if(Math.asin(bm" ascii
    $s15 = "stIndexOf(\"15239\") != -1){var c2 = false;}var t = mNM(\"03261b0a\", \"pCung7QN\");function lUp(Is){return Math.cos(Is);}var ZN" ascii
    $s16 = " -1;if(Math.cos(s3O) > 0){var woD = \"\";}else{var QwB = -43359;}var A8 = -1;if(Math.sin(A8) >= 0){kLJ = false;}var N1 = 0;if(Ma" ascii
    $s17 = "r BY = \"59620\";}var i6 = -1;if(Math.cos(i6) == 0){DCe = false;}else{D_ = '-45841';}return(Yn);}function QP(qz){if(\"\".length " ascii
    $s18 = "7 != -21203){zW = \"c84178\";}else{var Du = '';}function vj(mz){return Math.sin(mz);}var qz = QP(P);function VZ(_r){return Math." ascii
    $s19 = "cene\".length <= -55214){BqO = -2524;}var Zty = -1;if(Math.sin(Zty) > 0){var kZP = -30682;}else{var w2 = \"-50405\";}if(\"cosmos" ascii
    $s20 = "= 1;var PYw = 1;if(Math.cos(PYw) > 0){var CR = '8b4992';}var Zd = 0;if(Math.asin(Zd) == 0){dQ = -6461;}else{mo = '';}var NiK = 0" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}