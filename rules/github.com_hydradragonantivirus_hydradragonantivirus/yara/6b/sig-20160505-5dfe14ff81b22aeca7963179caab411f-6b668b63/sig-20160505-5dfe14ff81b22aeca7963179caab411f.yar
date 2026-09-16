rule sig_20160505_5dfe14ff81b22aeca7963179caab411f {
  meta:
    description = "datamaliciousorder - file 20160505_5dfe14ff81b22aeca7963179caab411f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f44aca973db2cad69daeef6e068de8cbdcb8f6feb2233202b1135de65fbe0da1"

  strings:
    $x1  = "function IM(ef, dc){function s_R(xk, Z){return Math.atan2(xk, Z);}function boP(rQT){return Math.sqrt(rQT);}if(\"7244\".length >=" ascii
    $s2  = "\\x39\\x61\\x30\\x34\\x37\\x36\\x38\\x35\".length == -5918){var Y_ = true;}function Na(LOT){return Math.log(LOT);}var R = IM(\"0" ascii
    $s3  = "\"2fc69c3\";}var tf = 0;if(Math.sin(tf) == 0){var NuI = '-18194';}function FU(Fn){return Math.log(Fn);}var dL = -1;if(Math.cos(d" ascii
    $s4  = "seInt(-2173);}else{ka = \"\\x61\\x32\\x34\\x61\\x32\\x33\\x66\";}function Io(LM9){return Math.log(LM9);}var i = IM(\"191017\", " ascii
    $s5  = "t(38625);}var zNd = -1;if(Math.sin(zNd) >= 0){var hOI = true;}var vI = IM(\"1910170f09155857\", \"key\");if(\"61508\".length ===" ascii
    $s6  = " 1;if(Math.sin(JcW) > 0){cX = \"-12710\";}else{var cp = '-63909';}var K = IM(\"18040f0e11160d0c150e\", \"key\");var zIO = -1;if(" ascii
    $s7  = "811181f100a\", \"key\");var GD = 0;if(Math.acos(GD) != 0){var lG = 30145;}else{var yXq = '2738';}var tmJ = -1;if(Math.sin(tmJ) >" ascii
    $s8  = " 0){var jm = 63333;}function RJ(N4){return Math.floor(N4);}var yvA = HW + \"\\\\\" + f + \".\" + wmr;var FX = -1;if(Math.asin(FX" ascii
    $s9  = "return Math.sqrt(yz8);}if(P[_e] == 1){var FC = -1;if(Math.sin(FC) != 0){tU = 'd67b50e6';}function JvR(SW){return Math.abs(SW);}i" ascii
    $s10 = "(\"0809161800\", \"key\");var deL = -1;if(Math.acos(deL) != 0){yqr = \"-64622\";}else{ql = parseInt(1000000001110010, 2);}var NZ" ascii
    $s11 = "71, 8);}else{WaE = '';}var TSj = -1;if(Math.sin(TSj) === 0){PV = \"\\x34\\x38\\x62\\x30\\x63\\x31\\x65\";}if(\"\\x31\\x65\\x33" ascii
    $s12 = "{azS = false;}else{YmR = '';}var zVS = -1;if(Math.acos(zVS) === 0){var nAl = \"-11846\";}var OXd = 1;if(Math.cos(OXd) == 0){faw " ascii
    $s13 = "var Va = false;}else{yi = false;}var hY = -1;if(Math.sin(hY) > 0){Inz = \"-22862\";}else{var Daq = 'analyze';}function JGD(EbJ){" ascii
    $s14 = "++){if(\"66a7bb\".length === 3604){aZ = \"34939\";}else{WcN = false;}var yKO = -1;if(Math.sin(yKO) != 0){var Bp = parseInt(11111" ascii
    $s15 = " = 0;if(Math.cos(HWN) == 0){Xp = '\\x62\\x30\\x66\\x37\\x65';}var ERr = -1;if(Math.acos(ERr) == 0){var Ozt = -53571;}else{var qw" ascii
    $s16 = "8);}else{var S3U = \"\";}var Tp_ = -1;if(Math.asin(Tp_) != 0){Nr = true;}var BI = 0;if(Math.cos(BI) == 0){OU = true;}else{var gH" ascii
    $s17 = "-19048);}var Sly = -1;if(Math.sin(Sly) === 0){nH = \"lakes\";}return(f);}function ldS(ef, dc){if(\"0366cd\" != \"9b6e0fb5\"){var" ascii
    $s18 = "=== 0){var iw = false;}var MM = -1;if(Math.asin(MM) != 0){var DW = parseInt(-48391);}var wmr = IM(\"0e1d1c\", \"key\");}var bA =" ascii
    $s19 = "true;}if(\"\".length < -17632){var cuO = 037777657744;}var K7X = 1;if(Math.sin(K7X) > 0){sDF = 037777753401;}else{var XkR = true" ascii
    $s20 = ".lastIndexOf(\"supports\") == -1){Dp = \"26860\";}function kQ(no){return Math.asin(no);}if(\"\\x65\\x62\\x35\\x61\\x32\\x36\\x66" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}