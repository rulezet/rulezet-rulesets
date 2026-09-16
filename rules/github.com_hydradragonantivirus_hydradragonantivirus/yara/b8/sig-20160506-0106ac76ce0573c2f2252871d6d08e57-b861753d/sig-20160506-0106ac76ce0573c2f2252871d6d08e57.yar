rule sig_20160506_0106ac76ce0573c2f2252871d6d08e57 {
  meta:
    description = "datamaliciousorder - file 20160506_0106ac76ce0573c2f2252871d6d08e57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6dc09d20914f18438916aec898c2f4e46c2e4bf660d66667737ffeae805964d7"

  strings:
    $s1  = "function WM(SW1, l){var qnf = -1;if(Math.asin(qnf) >= 0){var UN_ = '-45830';}var N = \"\\x61\\x39\\x66\\x64\\x34\\x64\\x65\";if(" ascii
    $s2  = "var oF = 1;if(Math.sin(oF) != 0){P6 = true;}var aS = lW[f];function R6X(R4){return Math.log(R4);}var BFf = -1;if(Math.cos(BFf) >" ascii
    $s3  = "{var Ev = 'bullet';}else{Udi = '0f06b38';}function JAw(tKu){return Math.log(tKu);}if(\"\\x37\\x63\\x38\\x36\\x31\\x36\".indexOf(" ascii
    $s4  = "ath.sin(KgB) > 0){var lt = \"\\x39\\x37\\x36\\x33\\x36\";}else{QG = \"9912aa9a\";}if(\"\".lastIndexOf(\"19892cd2\") == -1){var M" ascii
    $s5  = "6\\x36\\x38\\x63\\x30\\x63\\x33\\x30\";}T[MY4](IR);var S8 = -1;if(Math.cos(S8) == 0){_s = true;}var aue = \"portsmouth\";var XE " ascii
    $s6  = " ks = Math.floor(Math.random() * 65536);var ni = 0;if(Math.acos(ni) != 0){NF = 3979;}else{bpQ = '53907';}var CUs = 1;if(Math.cos" ascii
    $s7  = "\"\";if(gut === \"b7c34\"){var ZnL = -26461;}else{var ony = '-37811';}var NK = -1;if(Math.sin(NK) > 0){var II = '\\x30\\x61\\x62" ascii
    $s8  = "(\"heartache\") == 0){cru = true;}else{J3 = '-59206';}var lb = -1;if(Math.cos(lb) >= 0){cN = true;}continue;}if(parseInt(-28697)" ascii
    $s9  = "h; YN++){var fH = -1;if(Math.sin(fH) === 0){var NA = 'e2e71b';}var AR = 1;if(Math.acos(AR) == 0){var Up = false;}else{LOn = true" ascii
    $s10 = "83){gL = 0x1cc2;}else{QP = parseInt(37777676445, 8);}var vce = -1;if(Math.sin(vce) === 0){var gwd = '';}else{var dm = true;}var " ascii
    $s11 = "-1;if(Math.asin(J6S) > 0){Jux = '42396';}else{ATU = true;}var Cpe = -1;if(Math.cos(Cpe) != 0){var LM = 0110407;}var KgB = 1;if(M" ascii
    $s12 = "_FT = -1;if(Math.sin(_FT) >= 0){var aWw = '46851';}else{var gX = false;}var UqW = 1;if(Math.asin(UqW) == 0){var XBY = 44217;}els" ascii
    $s13 = ".asin(zK) === 0){var lnM = 0x7754;}var CPU = -1;if(Math.sin(CPU) != 0){px = true;}var qG = 1;if(Math.sin(qG) >= 0){var xg = -205" ascii
    $s14 = "ar fC = -1;if(Math.sin(fC) != 0){var FcL = '-62147';}else{var dEk = false;}var SN = 0;if(Math.sin(SN) >= 0){ch = 21246;}var sJ =" ascii
    $s15 = "1\\x39\\x65\\x63\\x32\".lastIndexOf(\"falsetto\") > 0){sYF = \"crease\";}else{VN = -52239;}function GL(aFY){return Math.tan(aFY)" ascii
    $s16 = ";if(Math.cos(z4E) != 0){var zC = \"unconventional\";}function Y7T(hSS){return Math.ceil(hSS);}if(\"2256\".length > -41458){jV = " ascii
    $s17 = "c6a8\";}else{Th = parseInt(-10289);}var fe = -1;if(Math.cos(fe) >= 0){Um = 0123534;}else{var fT = \"better\";}if(\"21083\".index" ascii
    $s18 = "x63\\x37\\x32\\x37\\x31\\x35';}var eYV = -1;if(Math.sin(eYV) != 0){WS = parseInt(11222);}else{var IOk = true;}var rx = \"\\x35" ascii
    $s19 = "tIndexOf(\"therapy\") != -1){var JZ = parseInt(47277);}else{cSW = parseInt(37777765366, 8);}var tfm = -1;if(Math.cos(tfm) == 0){" ascii
    $s20 = "}var J = tx[3];var uq = 0;if(Math.cos(uq) > 0){IV = 'mountebank';}else{var yi = -55451;}var qw = 1;if(Math.cos(qw) != 0){var mG " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}