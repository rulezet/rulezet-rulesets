rule sig_20160303_e988735561c2d355956770d8e24c6303 {
  meta:
    description = "datamaliciousorder - file 20160303_e988735561c2d355956770d8e24c6303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70a7077b04daa44856bc93084f4eeb1ef70cb1e0982fd60cf56dbf3cbdd5ef4b"

  strings:
    $s1  = "var TksmZ = \"dUBNGO sew pt.Shell unSOCWQ Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var WFw = (KFd + \"TTP\" + \" CtymJKF FYObE XML ream St rnkmbHpr AD sQSfwlw OD\").split(\" \");" fullword ascii
    $s3  = "var NS = true  , imbT = WFw[7] + \"\" + WFw[9];" fullword ascii
    $s4  = "return BkWoRnR[0] + BkWoRnR[2] + BkWoRnR[4] + \".F\" + BkWoRnR[7] + BkWoRnR[9] + BkWoRnR[12] + BkWoRnR[14];" fullword ascii
    $s5  = "var BkWoRnR = \"Sc xuAWcOw r pnXSAqPya ipting AQOGftK bkI ile MhoJgjGGJGiSmP System dS TFIge Obj PMWdzX ect trrMPGW\".split(\" " ascii
    $s6  = "bpOwM.open(ANcFB,LHaMn,false);" fullword ascii
    $s7  = "function qcCZxBaRR(RghYG,fnccT,IEtFS) {" fullword ascii
    $s8  = "function adkZ(CTVqt) {" fullword ascii
    $s9  = "vzp = v; break; " fullword ascii
    $s10 = "function gOiZMKg(LFqy) {" fullword ascii
    $s11 = "return rl.ExpandEnvironmentStrings(TksmZ[6]);" fullword ascii
    $s12 = "function oDbpZGwVr(czEhXzisuqs) {" fullword ascii
    $s13 = "return cQNF.responseBody;" fullword ascii
    $s14 = "function OBMs(cgUFM) {" fullword ascii
    $s15 = "function eIAB(OtXyN,ceJmw) {" fullword ascii
    $s16 = "function kLNx(CzsZK) {" fullword ascii
    $s17 = "function hqRlJ(EewKOO) {" fullword ascii
    $s18 = "function fpwZ(MGHlu) {" fullword ascii
    $s19 = "function vQmI(LIPdh) {" fullword ascii
    $s20 = "return OmNIDMj" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}