rule sig_20160313_924bb26758fd2627ab176ce716406a30 {
  meta:
    description = "datamaliciousorder - file 20160313_924bb26758fd2627ab176ce716406a30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79afb623d880f672a2298cbe740f202ba6df415c9383ccd8e278bc7af08de424"

  strings:
    $s1  = "var Zl = true  , vjlu = jnO[7] + jnO[9] + jnO[11];" fullword ascii
    $s2  = "return eyCErQB[0] + eyCErQB[2] + eyCErQB[4] + \".F\" + eyCErQB[7] + eyCErQB[9] + eyCErQB[12] + eyCErQB[14];" fullword ascii
    $s3  = "Wjwsd.open(wyMwd,wzqda,false);" fullword ascii
    $s4  = "var jnO = (\"2.XMLHTTP JgUEePF SYWec XML ream St BFxriwga AD NezjzGb O evuG D\").split(\" \");" fullword ascii
    $s5  = "var eyCErQB = \"Sc WNlyInB r AYxNOkqzL ipting ObudPHD qbV ile hGYKYgvSCiABLw System Ng vNIJb Obj jFfGsO ect LHOINgU\".split(\" " ascii
    $s6  = "function lVKgV(nIRHCB) {" fullword ascii
    $s7  = "function ZMgE(AZXVD) {" fullword ascii
    $s8  = "return mPQmgME" fullword ascii
    $s9  = "if(r>=N.length) {break;}" fullword ascii
    $s10 = "if (I >= AZXVD.length) {break;}" fullword ascii
    $s11 = "function NNlLnPeO() {" fullword ascii
    $s12 = "return YqF.size;" fullword ascii
    $s13 = "function yNSl(uQMPo) {" fullword ascii
    $s14 = "return iAsdV;" fullword ascii
    $s15 = "function SJrJ(Wjwsd,wzqda,wyMwd) {" fullword ascii
    $s16 = "function GBkp(rCyUc,UeHjM) {" fullword ascii
    $s17 = "function qCCR(tdVMv) {" fullword ascii
    $s18 = "function WbGYXiPxY(XfcNUjqjmtX) {" fullword ascii
    $s19 = "return pxZg.ExpandEnvironmentStrings(DharT);" fullword ascii
    $s20 = "if (uQMPo > 159766-110){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}