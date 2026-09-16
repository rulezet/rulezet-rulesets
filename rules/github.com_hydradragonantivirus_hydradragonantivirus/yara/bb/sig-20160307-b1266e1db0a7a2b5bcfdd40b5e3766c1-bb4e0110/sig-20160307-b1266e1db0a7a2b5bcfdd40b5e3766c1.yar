rule sig_20160307_b1266e1db0a7a2b5bcfdd40b5e3766c1 {
  meta:
    description = "datamaliciousorder - file 20160307_b1266e1db0a7a2b5bcfdd40b5e3766c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a590788672b37eff5204acd2bd056fb23803b2aa567f2fd7d4ba2ab45ee59cf5"

  strings:
    $s1  = "var mt = true  , xeiB = OSs[7] + OSs[9] + OSs[11];" fullword ascii
    $s2  = "return ESkTDyZ[0] + ESkTDyZ[2] + ESkTDyZ[4] + \".F\" + ESkTDyZ[7] + ESkTDyZ[9] + ESkTDyZ[12] + ESkTDyZ[14];" fullword ascii
    $s3  = "var ESkTDyZ = \"Sc dwIVxvY r fePanyvaZ ipting fZFBvJS MeR ile xLaRZVDVfbzOlJ System Ad Jqlzi Obj jYFSIf ect ZBliXhY\".split(\" " ascii
    $s4  = "var OSs = (\"2.XMLHTTP VEKQYiV moryJ XML ream St TEbYJDMC AD aNjYQcs O abBH D\").split(\" \");" fullword ascii
    $s5  = "return Ha.ExpandEnvironmentStrings(xDEtf[6]+xDEtf[7]+xDEtf[8]);" fullword ascii
    $s6  = "function uAOIIVCbv(XcRdP,nRbIx,uaGBs,tbxj) {" fullword ascii
    $s7  = "function EhZzButw() {" fullword ascii
    $s8  = "function DKAX(MGpsa) {" fullword ascii
    $s9  = "return HKdYV.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s10 = "return new ActiveXObject(IUfqKw);" fullword ascii
    $s11 = "function bVXP(xoTrr) {" fullword ascii
    $s12 = "return fDLquLg" fullword ascii
    $s13 = "function qGmVQ(IUfqKw) {" fullword ascii
    $s14 = "if (xoTrr > 183997-466){return true;} else {return false;}" fullword ascii
    $s15 = "function xDTkoKE(Txdu) {" fullword ascii
    $s16 = "if (XCWMD == 787-587){return true;} else {return false;}" fullword ascii
    $s17 = "function iCyR(XCWMD) {" fullword ascii
    $s18 = "function pzbTemRtB(KLpECbpGMZC) {" fullword ascii
    $s19 = "function qnmh(HasfL) {" fullword ascii
    $s20 = "return HasfL.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}