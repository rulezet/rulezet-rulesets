rule sig_20160314_708b84696035968b6739a88588425dab {
  meta:
    description = "datamaliciousorder - file 20160314_708b84696035968b6739a88588425dab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "349b3d050f03d50361228d313439517592b8364ada6e5918a8e4ce2d739bd89a"

  strings:
    $s1  = "var av = true  , cVmm = mpv[7] + mpv[9] + mpv[11];" fullword ascii
    $s2  = "return EZBSVRV[0] + EZBSVRV[2] + EZBSVRV[4] + \".F\" + EZBSVRV[7] + EZBSVRV[9] + EZBSVRV[12] + EZBSVRV[14];" fullword ascii
    $s3  = "var EZBSVRV = \"Sc AQmbYqY r QEBUThUgp ipting FniGIbY pEk ile CvWQekxZPSILJY System qY qLEdV Obj ANWIsB ect jGYBEqC uecvY\".spli" ascii
    $s4  = "var mpv = (\"2.XMLHTTP TOgMPDc OLdnq XML ream St YXtPBBeS AD kXIgaMo O hQzr D\").split(\" \");" fullword ascii
    $s5  = "var EZBSVRV = \"Sc AQmbYqY r QEBUThUgp ipting FniGIbY pEk ile CvWQekxZPSILJY System qY qLEdV Obj ANWIsB ect jGYBEqC uecvY\".spli" ascii
    $s6  = "ooRQB.open(wqJiB,lgImt,false);" fullword ascii
    $s7  = "function NCsNlMiu() {" fullword ascii
    $s8  = "if (PBAaE == 417-217){return true;} else {return false;}" fullword ascii
    $s9  = "return AJgewfF" fullword ascii
    $s10 = "if (aCoql > 163204-105){return true;} else {return false;}" fullword ascii
    $s11 = "function lyPY(ESAtb,oEaOc) {" fullword ascii
    $s12 = "function HNWcKBTwj() {" fullword ascii
    $s13 = "function CijUaXQO(Fpu) {" fullword ascii
    $s14 = "return LtbQS;" fullword ascii
    $s15 = "JsQ = o; break; " fullword ascii
    $s16 = "function bOTa(vWwDn) {" fullword ascii
    $s17 = "function ImxG(nQEaM) {" fullword ascii
    $s18 = "if(o>=c.length) {break;}" fullword ascii
    $s19 = "if (Z >= XcSPs.length) {break;}" fullword ascii
    $s20 = "return PPAp.ExpandEnvironmentStrings(oyQCI);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}