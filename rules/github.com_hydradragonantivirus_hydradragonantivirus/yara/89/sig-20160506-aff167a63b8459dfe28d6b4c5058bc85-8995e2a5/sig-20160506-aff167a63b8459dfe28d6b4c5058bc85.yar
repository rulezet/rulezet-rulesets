rule sig_20160506_aff167a63b8459dfe28d6b4c5058bc85 {
  meta:
    description = "datamaliciousorder - file 20160506_aff167a63b8459dfe28d6b4c5058bc85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d907f72651de62cd5f578c1864630939b1764b34c7ffffd2be9d3ebff78d50fa"

  strings:
    $x1  = "function MXY(){if(-28451 < parseInt(-52448)){var oQA = true;}else{Ql = false;}if(\"\".indexOf(\"-46130\") == -1){var O3X = false" ascii
    $s2  = "HWG){return Math.sqrt(HWG);}var hlr = -1;if(Math.acos(hlr) >= 0){rIi = -29704;}if(yF[oN] == 1){function dpQ(nV){return Math.log(" ascii
    $s3  = "51697)){Ll = false;}function pG6(W5n){return Math.log(W5n);}var mtG = \"-35073\";if(mtG === \"457c75\"){var xa = true;}else{var " ascii
    $s4  = "= 0){Bzz = parseInt(-29643);}if(\"\" === \"\\x65\\x39\\x32\\x34\\x35\"){var vr5 = false;}NEI = NEI + 1;var Gxh = -1;if(Math.sin(" ascii
    $s5  = "se{var zh = '706';}var Ws = -1;if(Math.cos(Ws) == 0){var NzN = 56047;}else{var W8W = \"-18533\";}var u = Math.floor(Math.random(" ascii
    $s6  = "= 48650;}var w0 = -1;if(Math.sin(w0) >= 0){G6 = true;}else{var ZM = \"\";}var Jv = 1;if(Math.sin(Jv) >= 0){var fz = '-16427';}re" ascii
    $s7  = "else{var Rzd = 49934;}var Oe = -1;if(Math.sin(Oe) >= 0){var DvI = \"\\x65\\x35\\x39\\x64\\x62\\x65\\x36\";}else{var eoV = parseI" ascii
    $s8  = "= -55423;}Va[fQ] = 1;var jqo = -1;if(Math.sin(jqo) >= 0){var J_C = 1238;}else{Y7d = parseInt(-39353);}var qUk = -1;if(Math.acos(" ascii
    $s9  = "xk[JRs].substr(0, 2);if(parseInt(-25952) != -52460){fqi = true;}var Fn = 0;if(Math.asin(Fn) >= 0){cI = 'perversion';}else{var vQ" ascii
    $s10 = "0){Gib = '8141';}function QJ(ri){return Math.ceil(ri);}if(\"-61171\".indexOf(\"6294\") == -1){Tq = -8745;}var GTM = 1;if(Math.si" ascii
    $s11 = "1d1d33352c393808010d33\", \"nGPAVZbd\");var KiN = -1;if(Math.cos(KiN) != 0){WBR = 21827;}else{XXW = \"e82ba72\";}if(\"-54464\".l" ascii
    $s12 = " = -1;if(Math.sin(bmE) == 0){sYF = \"\\x64\\x38\\x39\\x37\\x37\";}function WgL(aFY){return Math.ceil(aFY);}if(\"\\x38\\x36\\x66" ascii
    $s13 = "w1j){return Math.asin(w1j);}}}}function uUr(RzY, O){var _fd = 1;if(Math.cos(_fd) > 0){var fyE = \"asin\";}else{var GB = -7267;}v" ascii
    $s14 = "WLEyN\");var wyv = -1;if(Math.acos(wyv) == 0){var m6 = parseInt(37777650214, 8);}else{Qw = true;}var lPU = 1;if(Math.sin(lPU) ==" ascii
    $s15 = "42012\"){puc = true;}else{var SFb = \"\";}var jfA = -1;if(Math.sin(jfA) == 0){var As = \"2692\";}var BZR = 0;if(Math.cos(BZR) ==" ascii
    $s16 = "y = true;}var Lsh = 1;if(Math.cos(Lsh) > 0){var pcE = -57078;}else{var d_ = \"05442\";}if(EP == 0){var Rwh = -1;if(Math.asin(Rwh" ascii
    $s17 = "!= -1){bzb = false;}else{var JuC = \"coleman\";}function Xyi(oV){return Math.sin(oV);}var UY = \"\\x32\\x63\\x34\\x33\\x39\\x62" ascii
    $s18 = "(FAh){return Math.sin(FAh);}var xn = 1;if(Math.acos(xn) != 0){YF = true;}var N6 = N6.split(\",\");var Wr = -1;if(Math.acos(Wr) >" ascii
    $s19 = "(Math.cos(hr2) == 0){mu = true;}else{var r3 = '62745';}if(0x4654 >= -57310){var xr = '-60368';}if(\"21cf1\".length >= -17220){va" ascii
    $s20 = "= false;}p[Lis](m, 1, 0);break;}if(-17042 <= -27087){V7p = parseInt(44844);}var bop = -1;if(Math.cos(bop) === 0){Jht = true;}els" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}