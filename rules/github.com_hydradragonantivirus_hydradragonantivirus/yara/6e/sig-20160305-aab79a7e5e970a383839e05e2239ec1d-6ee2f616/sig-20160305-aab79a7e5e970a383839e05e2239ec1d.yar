rule sig_20160305_aab79a7e5e970a383839e05e2239ec1d {
  meta:
    description = "datamaliciousorder - file 20160305_aab79a7e5e970a383839e05e2239ec1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5c5e11cc2e917e829648e397a80918a76088a8ae3c37d4fef49222fba0bb5c8"

  strings:
    $s1  = "var UHFAy = \"NsOEAG qLK pt.Shell tbYpYpT Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return wTrwGvf[0] + wTrwGvf[2] + wTrwGvf[4] + \".F\" + wTrwGvf[7] + wTrwGvf[9] + wTrwGvf[12] + wTrwGvf[14];" fullword ascii
    $s3  = "var aR = true  , SBmG = ayP[7] + \"\" + ayP[9];" fullword ascii
    $s4  = "var ayP = (ztd + \"TTP\" + \" TTtYDlO KnDph XML ream St aXBPWLmR AD GhROQIt OD\").split(\" \");" fullword ascii
    $s5  = "ohwhc.open(vZYld,vdGML,false);" fullword ascii
    $s6  = "var wTrwGvf = \"Sc mpPNQud r GBwkXQqzu ipting EqSVDcj Hdz ile tkkyibWvKYobcW System av spLFh Obj utKoFx ect LefpCpp\".split(\" " ascii
    $s7  = "if(N>=Q.length) {break;}" fullword ascii
    $s8  = "function RMQSpGs(zopJ) {" fullword ascii
    $s9  = "function RbDO(xQiHG) {" fullword ascii
    $s10 = "function oPfLCBtJZ(sKeMxGSlxaB) {" fullword ascii
    $s11 = "return new ActiveXObject(BtcuPo);" fullword ascii
    $s12 = "return NoiPa.status;" fullword ascii
    $s13 = "function ETHe(NoiPa) {" fullword ascii
    $s14 = "function Acyb(NYGLZ,YVmIm) {" fullword ascii
    $s15 = "function suih(bZxXL) {" fullword ascii
    $s16 = "function cMrSTgT(BXWz) {" fullword ascii
    $s17 = "function gEpq(YWzBR) {" fullword ascii
    $s18 = "function mToK(riEDv) {" fullword ascii
    $s19 = "if (((new Date())>0,7857192888)) {" fullword ascii
    $s20 = "function ERog(CxvCC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}