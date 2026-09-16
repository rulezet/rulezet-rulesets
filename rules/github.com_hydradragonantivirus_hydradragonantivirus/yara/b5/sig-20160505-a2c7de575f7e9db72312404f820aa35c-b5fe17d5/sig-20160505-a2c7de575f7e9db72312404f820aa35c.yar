rule sig_20160505_a2c7de575f7e9db72312404f820aa35c {
  meta:
    description = "datamaliciousorder - file 20160505_a2c7de575f7e9db72312404f820aa35c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0359197c51f090b6536df32f6faad3aa04bdea911a3649b535fbadc10357f1c2"

  strings:
    $x1  = "function gre(){try{Nn = 'c801f';}catch(ukd){var VQ = 0xffff17dc;}finally{d2 = 011404;}var oA = 0;if(Math.cos(oA) >= 0){var WUJ =" ascii
    $s2  = "th.cos(Sps) >= 0){lKa = -21985;}else{Dl = '\\x63\\x39\\x35\\x64\\x36\\x32\\x63\\x36';}function CWk(hxE){return Math.log(hxE);}if" ascii
    $s3  = "ath.floor(Math.random() * 65536);function dIr(pO){return Math.tan(pO);}var TQ = -1;if(Math.asin(TQ) > 0){var Ow5 = \"-8703\";}el" ascii
    $s4  = "7\", \"key\");if(\"48321\".indexOf(\"29602\") != -1){mIq = \"usages\";}if(\"specs\".length === 0xffff1c56){var ad = '-31806';}el" ascii
    $s5  = "= \"3e10f9\";}else{m_e = parseInt(-35744);}var GDW = VR(VBo);function yU(Hl){return Math.log(Hl);}if(0xffff7d87 == 0xffff9628){v" ascii
    $s6  = "1952\";}var T = lr(ZQ4, S);function mJ(Un){return Math.log(Un);}if(parseInt(37777626132, 8) < 0xffff5371){var wXA = '\\x63\\x63" ascii
    $s7  = "nd(Mf);}if(0x9d26 > parseInt(1111001111111010, 2)){nKm = '';}else{Th = true;}JGs = JGs + 1;var Jn = -1;if(Math.sin(Jn) == 0){var" ascii
    $s8  = "111111110110000111101001, 2);}var Oj = k(\"18040f0e11160d0c150e\", \"key\");var JcW = -1;if(Math.sin(JcW) > 0){var pg = false;}e" ascii
    $s9  = "0111011010100101, 2)){var Jc = \"\\x35\\x64\\x66\\x66\\x61\\x30\\x35\\x39\";}else{nWj = \"obsession\";}var v3 = -1;if(Math.cos(v" ascii
    $s10 = " = parseInt(57422, 8);}var pC = -1;if(Math.cos(pC) > 0){var FMw = 021523;}else{var _fZ = 0x5e31;}var B = k(\"1800170f\", \"key\"" ascii
    $s11 = "\\x32\\x38\\x39\\x64';}if(\"-25464\".length <= 31266){var uq = 'semicircle';}else{Zw = '';}return(T);}function VR(CbO){var CR = " ascii
    $s12 = "7\\x31\".lastIndexOf(\"\") == -1){var ktD = parseInt(61582);}else{var AVh = \"keyword\";}var djt = 1;if(Math.cos(djt) == 0){ThN " ascii
    $s13 = "= k(\"1811181f100a\", \"key\");function gfY(mVB){return Math.round(mVB);}function nk(YV){return Math.sin(YV);}var Ud = -1;if(Mat" ascii
    $s14 = "parseInt(-35847)){HK = \"649f\";}var Did = 1;if(Math.asin(Did) == 0){um = false;}var Qv = -1;if(Math.sin(Qv) == 0){iW = 'keynote" ascii
    $s15 = "JxB = 0;if(Math.sin(JxB) != 0){var ILV = false;}else{var pRi = parseInt(11111111111111111001101100011011, 2);}var NCV = -1;if(Ma" ascii
    $s16 = "th <= parseInt(11111111111111111000110000110011, 2)){jp = true;}else{var Qod = \"\";}var ab = -1;if(Math.cos(ab) != 0){He = 0xff" ascii
    $s17 = "\"\\x37\\x34\\x37\\x63\" === \"\"){gc = true;}var zVS = k(\"0c000d18151c080c1807031607011c19\", \"key\");var VG = 0;if(Math.cos(" ascii
    $s18 = "r Q_m = -1;if(Math.sin(Q_m) === 0){var Fzp = '-19572';}function yw(ncE){return Math.sin(ncE);}var pP = \"-39264\";if(pP != \"ver" ascii
    $s19 = "}else{var ef = 63671;}var h = -1;if(Math.sin(h) === 0){LIu = '\\x33\\x36\\x33\\x61\\x63\\x39\\x31\\x61';}if(\"legitimacy\".lengt" ascii
    $s20 = " -1){var am = true;}var rlZ = 0;if(Math.sin(rlZ) > 0){var Ze_ = parseInt(-36660);}function wCw(ue){return Math.asin(ue);}var YD8" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}