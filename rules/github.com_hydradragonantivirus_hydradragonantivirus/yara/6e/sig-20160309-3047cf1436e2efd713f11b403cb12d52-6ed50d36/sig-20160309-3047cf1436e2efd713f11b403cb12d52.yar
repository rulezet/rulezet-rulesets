rule sig_20160309_3047cf1436e2efd713f11b403cb12d52 {
  meta:
    description = "datamaliciousorder - file 20160309_3047cf1436e2efd713f11b403cb12d52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ef77976f3b9bbe98f283758946265ec00879d95e5fb046f211d91617c2173c"

  strings:
    $s1  = "return NgetwGY" fullword ascii
    $s2  = "var pa = true  , oXlZ = bwm[7] + bwm[9] + bwm[11];" fullword ascii
    $s3  = "return VFxqAqn[0] + VFxqAqn[2] + VFxqAqn[4] + \".F\" + VFxqAqn[7] + VFxqAqn[9] + VFxqAqn[12] + VFxqAqn[14];" fullword ascii
    $s4  = "XxsJq.open(wRtbF,RJAyB,false);" fullword ascii
    $s5  = "var VFxqAqn = \"Sc bDlNAXN r RQHWRljYl ipting xJTbHpf cJs ile usbNpKifFREIPL System pX cdggT Obj qyzNPc ect TjedUZH\".split(\" " ascii
    $s6  = "var bwm = (\"2.XMLHTTP AxnJxFp xGYMo XML ream St WkMjXogx AD qktvglP O pOfD D\").split(\" \");" fullword ascii
    $s7  = "if (o >= qtRiM.length) {break;}" fullword ascii
    $s8  = "AgQ = x; break; " fullword ascii
    $s9  = "if (JJHch > 190676-714){return true;} else {return false;}" fullword ascii
    $s10 = "function BLfa(GBTvp,WDuZz) {" fullword ascii
    $s11 = "return ID.ExpandEnvironmentStrings(DCybq[6]+DCybq[7]+DCybq[8]);" fullword ascii
    $s12 = "function iGaJ(jAnUE) {" fullword ascii
    $s13 = "return FWEBZ.status;" fullword ascii
    $s14 = "function uyNgncbMG(yvRtmBwPVgP) {" fullword ascii
    $s15 = "function GSYo(FWEBZ) {" fullword ascii
    $s16 = "if (mCteC == 310-110){return true;} else {return false;}" fullword ascii
    $s17 = "function dQdMbfkZN(BOyvO,cXZuV,QzvUS,PZGE) {" fullword ascii
    $s18 = "function emdI(qtRiM) {" fullword ascii
    $s19 = "if(x>=f.length) {break;}" fullword ascii
    $s20 = "return IjLR.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}