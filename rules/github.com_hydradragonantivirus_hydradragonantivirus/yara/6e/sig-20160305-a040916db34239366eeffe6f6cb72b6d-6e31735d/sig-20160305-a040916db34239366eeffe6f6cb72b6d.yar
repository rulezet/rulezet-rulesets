rule sig_20160305_a040916db34239366eeffe6f6cb72b6d {
  meta:
    description = "datamaliciousorder - file 20160305_a040916db34239366eeffe6f6cb72b6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55431b36a7f3e7a3495838ade4b0f919c613913f60d0044601c0c255a9189135"

  strings:
    $s1  = "var ZqRvz = \"PjfLyD rdi pt.Shell SXJFssx Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var gfo = (eEV + \"TTP\" + \" MMjOYPa ocxlk XML ream St lodGprsE AD rrKvqLb OD\").split(\" \");" fullword ascii
    $s3  = "return iuptpSh[0] + iuptpSh[2] + iuptpSh[4] + \".F\" + iuptpSh[7] + iuptpSh[9] + iuptpSh[12] + iuptpSh[14];" fullword ascii
    $s4  = "var xM = true  , Smmu = gfo[7] + \"\" + gfo[9];" fullword ascii
    $s5  = "ijuOA.open(Qkmlq,zcGEH,false);" fullword ascii
    $s6  = "var iuptpSh = \"Sc HuhBZwp r PmRNcQNsu ipting YdcEXYR BgT ile ATGwELeABIciOi System qA HOnkA Obj QbMAqK ect kdJBDzX\".split(\" " ascii
    $s7  = "function MKKMS(qsTWIf) {" fullword ascii
    $s8  = "if (BpUML > 164903-315){return true;} else {return false;}" fullword ascii
    $s9  = "sPL = i; break; " fullword ascii
    $s10 = "function SlUXZnKTs(VQfGhfkfOld) {" fullword ascii
    $s11 = "function zNtC(Fhxyo) {" fullword ascii
    $s12 = "function IRzRYgjD() {" fullword ascii
    $s13 = "if (mZsHt == 1115-915){return true;} else {return false;}" fullword ascii
    $s14 = "function SUUQ(ZXVlp,NFNJg) {" fullword ascii
    $s15 = "function lXXe(IhjVL,muIIZ) {" fullword ascii
    $s16 = "function GBLE(ZpuMp) {" fullword ascii
    $s17 = "function BNMwdMp(QGMo) {" fullword ascii
    $s18 = "return pXRhm.status;" fullword ascii
    $s19 = "return Wg.ExpandEnvironmentStrings(ZqRvz[6]);" fullword ascii
    $s20 = "function SlqHORn(wsED) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}