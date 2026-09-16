rule sig_20160313_d600a723f0fc4d2a0f26d638b8cae663 {
  meta:
    description = "datamaliciousorder - file 20160313_d600a723f0fc4d2a0f26d638b8cae663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6dc5dc08e95b13be2a7c26947979776215cd8ca305d4cf711b0653e415e9e5a"

  strings:
    $s1  = "var Wg = true  , Lcfi = stB[7] + stB[9] + stB[11];" fullword ascii
    $s2  = "return apaZmMD[0] + apaZmMD[2] + apaZmMD[4] + \".F\" + apaZmMD[7] + apaZmMD[9] + apaZmMD[12] + apaZmMD[14];" fullword ascii
    $s3  = "var apaZmMD = \"Sc iGyjQvk r lplKFtQes ipting mmIJACU Fmx ile PyUUYwGPQsZPot System gd CwGsX Obj TwjULB ect dHHWnVU\".split(\" " ascii
    $s4  = "gNZOF.open(GRWqZ,glwss,false);" fullword ascii
    $s5  = "var stB = (\"2.XMLHTTP NccVITU tyFcz XML ream St yrLGkLNz AD vFJJoiA O Qfii D\").split(\" \");" fullword ascii
    $s6  = "return GhWZ.ExpandEnvironmentStrings(XYKje);" fullword ascii
    $s7  = "function iAIuO(phpvOZ) {" fullword ascii
    $s8  = "function hAguX(QxARbx) {" fullword ascii
    $s9  = "return XKCJc.status;" fullword ascii
    $s10 = "function fprR(qgfWL) {" fullword ascii
    $s11 = "function yswXRhDMk(HVMXSlrkSjx) {" fullword ascii
    $s12 = "return fHb.size;" fullword ascii
    $s13 = "function dqNd(klEMy,qmOEv) {" fullword ascii
    $s14 = "return new ActiveXObject(QxARbx);" fullword ascii
    $s15 = "if (yMjvv == 673-473){return true;} else {return false;}" fullword ascii
    $s16 = "return oNffldD(vX,veDnp[523-517]+veDnp[954-947]+veDnp[420-412]);" fullword ascii
    $s17 = "function wgGm(Wfzjn,mpPzA) {" fullword ascii
    $s18 = "function oNffldD(GhWZ,XYKje) {" fullword ascii
    $s19 = "function zXhPaKD(OmHj) {" fullword ascii
    $s20 = "if(v>=X.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}