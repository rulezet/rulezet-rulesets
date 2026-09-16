rule sig_20160506_da486c07cd6a209355ad23cc193d2e02 {
  meta:
    description = "datamaliciousorder - file 20160506_da486c07cd6a209355ad23cc193d2e02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ea968e46ebdb2b7cc2ea0312caafb1da70e478b22ccb3c96091344c96a1d88b"

  strings:
    $x1  = "function e(kul, c){var zQl = -1;if(Math.acos(zQl) >= 0){var a1 = 'insecurity';}else{tU4 = '\\x33\\x31\\x65\\x30\\x63\\x35';}var " ascii
    $s2  = "th.asin(asm);}function rnZ(_YD){return Math.exp(_YD);}function IU(zbS){return Math.log(zbS);}var lGY = -1;if(Math.cos(lGY) > 0){" ascii
    $s3  = "54173, 8);}else{ye = -36119;}var ac = j(\"3c1f2d2b\", \"SoHEz5I\");function ct(mL){return Math.log(mL);}if(\"choral\".indexOf(\"" ascii
    $s4  = "== R7t){var H_ = true;}else{yD = true;}function TS(icP){return Math.log(icP);}var ew = j(\"35375d05\", \"FR3arvD\");function Vq3" ascii
    $s5  = "else{PY = \"-9944\";}for(Gk = 0; Gk < zmC.length; Gk++){try{function bL(tIL){return Math.log(tIL);}function tZJ(jl){return Math." ascii
    $s6  = "a5e575b252e17242e0b0b0422370222740717196224123c7401001131744f2d6b1848\", \"tMEvQZdx\");function Fs(hW){return Math.log(hW);}if(" ascii
    $s7  = "IndexOf(\"indoor\") != -1){var nyS = 16092;}var bj = 0;if(Math.asin(bj) == 0){yM = false;}var BAz = -1;if(Math.acos(BAz) === 0){" ascii
    $s8  = "(37777736751, 8)){var xi = true;}var Igu = \"-24296\";var xE = \"-45193\";if(Igu === xE){KT = '45632';}S8 = S8 + 1;var hBU = -1;" ascii
    $s9  = " = 36190;}var AKO = -1;if(Math.asin(AKO) != 0){var Ueo = true;}else{var xP = '30465';}var b = ij + \"\\\\\" + aC3 + \".\" + Z;va" ascii
    $s10 = "{var Y6 = true;}else{Dm = false;}var hr2 = -1;if(Math.sin(hr2) > 0){Qbq = false;}else{__d = '55280';}if(\"\".length <= 22572){va" ascii
    $s11 = "tK = parseInt(37777622620, 8);}else{var spx = parseInt(4525);}var ij = cK[ylh](2);var tv7 = -1;if(Math.sin(tv7) >= 0){qX = 01150" ascii
    $s12 = ";if(Math.asin(lb) === 0){cN = false;}if(\"\".indexOf(\"65e3\") == 0){u8x = '-15426';}var ZU = 0;if(Math.cos(ZU) == 0){var OpO = " ascii
    $s13 = "se{HNf = \"\";}var JPn = 1;if(Math.cos(JPn) >= 0){z05 = 'scribe';}var BYO = -1;if(Math.asin(BYO) != 0){lN = false;}var ATN = j(" ascii
    $s14 = "31\\x30\") > 0){var mD = false;}var Qn = -1;if(Math.sin(Qn) > 0){YL = \"dom\";}else{var WhY = '\\x39\\x31\\x30\\x32\\x34\\x35\\x" ascii
    $s15 = "74712, 8);}if(\"\\x34\\x36\\x30\\x30\\x66\\x61\".indexOf(\"ed4c\") != -1){Q1q = false;}var MCP = 0;if(Math.cos(MCP) != 0){var qf" ascii
    $s16 = ";}var nit = -1;if(Math.sin(nit) >= 0){var IC = -33434;}else{ds = parseInt(37777663703, 8);}var gFR = 0;if(Math.cos(gFR) > 0){lz " ascii
    $s17 = "unction yVG(eP){return Math.round(eP);}if(\"ec5c93\".indexOf(\"abides\") == 0){var axk = -5482;}var ID = 1;if(Math.sin(ID) == 0)" ascii
    $s18 = "m = \"\";}else{BIR = false;}if(\"-19122\" == \"41576\"){tFh = 'b095';}else{jJ = false;}var etl = -1;if(Math.sin(etl) >= 0){var h" ascii
    $s19 = "function hJq(Pqk){return Math.atan(Pqk);}var bYU = -1;if(Math.cos(bYU) === 0){var a5 = '-32583';}var zKn = j(\"17385e1c23\", \"t" ascii
    $s20 = "0;if(Math.cos(FM) != 0){var _C = '27715';}var GDB = 1;if(Math.cos(GDB) >= 0){CUh = true;}zY[zKn]();var O9h = -1;if(Math.asin(O9h" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}