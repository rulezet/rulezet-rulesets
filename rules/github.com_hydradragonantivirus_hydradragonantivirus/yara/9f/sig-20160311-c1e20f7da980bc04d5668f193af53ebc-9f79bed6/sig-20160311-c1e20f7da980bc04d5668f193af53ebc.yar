rule sig_20160311_c1e20f7da980bc04d5668f193af53ebc {
  meta:
    description = "datamaliciousorder - file 20160311_c1e20f7da980bc04d5668f193af53ebc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ac92831b762d36f168a858f44b27e2ad3d295eea1fc3a7032712a2bcef0e92"

  strings:
    $s1  = "return mKHkTGL[0] + mKHkTGL[2] + mKHkTGL[4] + \".F\" + mKHkTGL[7] + mKHkTGL[9] + mKHkTGL[12] + mKHkTGL[14];" fullword ascii
    $s2  = "var bQ = true  , RkDB = tnp[7] + tnp[9] + tnp[11];" fullword ascii
    $s3  = "var tnp = (\"2.XMLHTTP FuzcJGG CfFCf XML ream St WvfnDbTp AD aLgGFWp O kdmg D\").split(\" \");" fullword ascii
    $s4  = "var mKHkTGL = \"Sc zlFEjzE r BOjjdKGEl ipting nrSKsbQ HsY ile jQuEOQrcjyrxSp System KM YzfMd Obj OawGbk ect YUHywaR\".split(\" " ascii
    $s5  = "DdRmY.open(fliRN,rNQJy,false);" fullword ascii
    $s6  = "function btRCQmm(bupd,dzxTf) {" fullword ascii
    $s7  = "function TnPOt(skPCfi) {" fullword ascii
    $s8  = "function nChQsWRcz() {" fullword ascii
    $s9  = "function sYOY(rBWMb) {" fullword ascii
    $s10 = "return RQJz.responseBody;" fullword ascii
    $s11 = "function DKKR(orOKt,RpaoH) {" fullword ascii
    $s12 = "function qPbyC(kKoxbp) {" fullword ascii
    $s13 = "function KbXKNzPyT(pWiWehYyJzQ) {" fullword ascii
    $s14 = "function owoxvVhR(MuJ) {" fullword ascii
    $s15 = "dGZ = R; break; " fullword ascii
    $s16 = "function Okgo(gOukS) {" fullword ascii
    $s17 = "return MuJ.size;" fullword ascii
    $s18 = "if (u >= gOukS.length) {break;}" fullword ascii
    $s19 = "if (QpQAB == 797-597){return true;} else {return false;}" fullword ascii
    $s20 = "function uybg(njwgz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}