rule sig_20160309_71cae9e1a5ac6ec6ed491d19d5cef860 {
  meta:
    description = "datamaliciousorder - file 20160309_71cae9e1a5ac6ec6ed491d19d5cef860.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6aa30add7387bcf6bcf83fb726e02a52c341a2edbd33de5555afb384707ed3f"

  strings:
    $s1  = "return iumNGBy[0] + iumNGBy[2] + iumNGBy[4] + \".F\" + iumNGBy[7] + iumNGBy[9] + iumNGBy[12] + iumNGBy[14];" fullword ascii
    $s2  = "var VU = true  , zPai = ziD[7] + ziD[9] + ziD[11];" fullword ascii
    $s3  = "var ziD = (\"2.XMLHTTP gUSlJhs jlGbM XML ream St aaSwNerX AD rKXUyPi O NgsP D\").split(\" \");" fullword ascii
    $s4  = "xbSRG.open(sdhXf,soqTA,false);" fullword ascii
    $s5  = "var iumNGBy = \"Sc dAdPFMC r rqgGxtLCf ipting dJIJGDN XZx ile vfoGGZAlBtYMnY System hZ jvRal Obj XFREEQ ect ESeCKnZ\".split(\" " ascii
    $s6  = "function EauNn(jpvLgG) {" fullword ascii
    $s7  = "return ivQvPOb(KF,dSEfa[655-649]+dSEfa[561-554]+dSEfa[409-401]);" fullword ascii
    $s8  = "return uvxK.responseBody;" fullword ascii
    $s9  = "if (wRlSA == 401-201){return true;} else {return false;}" fullword ascii
    $s10 = "function YIgE(jrKya,lmfRY) {" fullword ascii
    $s11 = "function eQjr(RtsgV,wWice) {" fullword ascii
    $s12 = "function IBAWGVL(uvxK) {" fullword ascii
    $s13 = "function Ctdj(AlCSo) {" fullword ascii
    $s14 = "function TdwBgZbH() {" fullword ascii
    $s15 = "return TAVkO;" fullword ascii
    $s16 = "function ivQvPOb(vjrs,VYkOu) {" fullword ascii
    $s17 = "function rGwenXcFS(trrJaoiqdUG) {" fullword ascii
    $s18 = "return NDcxFCM" fullword ascii
    $s19 = "if (djlUf > 167363-587){return true;} else {return false;}" fullword ascii
    $s20 = "function wZeU(xIvuZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}