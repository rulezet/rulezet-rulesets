rule sig_20160506_fa19173019dde03989cbe75b2c8d2665 {
  meta:
    description = "datamaliciousorder - file 20160506_fa19173019dde03989cbe75b2c8d2665.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3af49dd373acb44248734f9a0a925278e04032cdaef33b5db23f4503ca7a886d"

  strings:
    $s1  = "function VU(s9, R){var Ra = 1;if(Math.cos(Ra) === 0){imL = \"cow\";}var I = 0;if(Math.asin(I) != 0){var Rzl = -34773;}else{var K" ascii
    $s2  = "TLH) > 0){PM = '';}function LPM(QP){return Math.log(QP);}if(\"-38319\".length <= -46766){var Qm = true;}wb[dS](SL);if(\"-27246\"" ascii
    $s3  = "{return Math.log(M8g);}var MSn = VU(\"122a26240a2c1d0c06673224163d071b123d3120153a1e07023d\", \"aITMzXtb\");var FrV = 0;if(Math." ascii
    $s4  = "turn Math.log(r_k);}if(\"\\x62\\x61\\x30\\x39\\x30\\x39\".indexOf(\"ea9dc6\") < 0){var e_T = false;}else{var PIm = 'hwy';}functi" ascii
    $s5  = "x38\\x35\\x66\";}var Ap = 0;if(Math.sin(Ap) >= 0){yb = \"49636\";}else{var dCG = '';}function dp(ZL){return Math.log(ZL);}if(\"-" ascii
    $s6  = "\\x66\\x63\";}var r3 = -1;if(Math.cos(r3) == 0){xZZ = \"-42764\";}else{var SYJ = '-619';}if(\"furtherance\".length === 2451){GV " ascii
    $s7  = "if(Math.cos(kK) == 0){B5 = -37195;}var Fjy = 1;if(Math.cos(Fjy) != 0){V_j = 'e884ee20';}else{oiQ = true;}if(\"-6037\".length > 3" ascii
    $s8  = "tion rrn(Xw){return Math.sin(Xw);}var sQ = new Function(fgV, KyN);if(0xffffe2b2 != -14893){var k = 'equation';}else{var u = '-18" ascii
    $s9  = "U(GR){return Math.cos(GR);}var Cf = -1;if(Math.sin(Cf) == 0){var Idd = \"\\x66\\x31\\x62\\x31\\x33\\x37\";}if(\"joker\" != \"\\x" ascii
    $s10 = "= true;}if(\"\".length <= 037777632146){fZF = \"figurative\";}var IL = 1;if(Math.sin(IL) != 0){APF = -35705;}var nkP = 1;if(Math" ascii
    $s11 = "){Qbq = true;}var dS = VU(\"45010d4722\", \"2sd3Gj\");if(\"\\x62\\x35\\x35\\x35\".length <= 0xde9a){k_c = false;}var TLH = -1;if" ascii
    $s12 = " parseInt(59387)){var Ep = true;}else{SkX = true;}var kx = -1;if(Math.sin(kx) != 0){E7 = \"16752\";}else{var YW9 = '-18351';}var" ascii
    $s13 = " \"WZtYyCn\");if(\"\\x33\\x37\\x38\\x33\\x36\".indexOf(\"respiratory\") < 0){Y_ = true;}else{XMu = -48221;}var wZ = -1;if(Math.c" ascii
    $s14 = "H);}return(cIr);}function ymQ(fgV, KyN){var IF = 0;if(Math.sin(IF) > 0){AkF = parseInt(1986);}var rI = -1;if(Math.cos(rI) === 0)" ascii
    $s15 = "a4 = '1721';}var Y = IOk[1];var dpQ = -1;if(Math.asin(dpQ) === 0){var bsz = true;}var sZ = 0;if(Math.cos(sZ) >= 0){var zwt = 177" ascii
    $s16 = " -43365;}else{zQ = parseInt(37777760552, 8);}var Fz = ig(s9);var CcW = 0;if(Math.cos(CcW) === 0){var X = 'trainer';}else{var r =" ascii
    $s17 = " '';}else{_dj = 'licenses';}var xW8 = -1;if(Math.cos(xW8) >= 0){var iVf = true;}var qcR = 0;if(Math.asin(qcR) === 0){RLQ = false" ascii
    $s18 = "function VU(s9, R){var Ra = 1;if(Math.cos(Ra) === 0){imL = \"cow\";}var I = 0;if(Math.asin(I) != 0){var Rzl = -34773;}else{var K" ascii
    $s19 = "6\".lastIndexOf(\"maritime\") == 0){Pd2 = '\\x66\\x62\\x64\\x36\\x30';}var Eb = -1;if(Math.sin(Eb) >= 0){var xV = true;}var AI =" ascii
    $s20 = "ge\";}for(bs = 0; bs < s9.length; bs++){var wC = -1;if(Math.cos(wC) == 0){var XU = false;}var cMs = -1;if(Math.asin(cMs) == 0){t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}