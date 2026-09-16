rule sig_20160315_57ea1f7fb098424a0386e2cd9d84fdea {
  meta:
    description = "datamaliciousorder - file 20160315_57ea1f7fb098424a0386e2cd9d84fdea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb5d057d3e13a295c00b73b33e1ad58b071e9f7b871cf8286531af86be85518c"

  strings:
    $s1  = "return uWPIGFc[0] + uWPIGFc[2] + uWPIGFc[4] + \".F\" + uWPIGFc[7] + uWPIGFc[9] + uWPIGFc[12] + uWPIGFc[14];" fullword ascii
    $s2  = "var iu = true  , hVdX = kkC[7] + kkC[9] + kkC[11];" fullword ascii
    $s3  = "var uWPIGFc = eZKjH(\"Sc nMrVdGZ r ZLNvmzPpg ipting MgYNkJx ULf ile RUYIZDAlpsTXjK System kR jYSLz Obj aEYABW ect yzrfhOU gzFPF" ascii
    $s4  = "EGvQn.open(xxrKe,EJDCQ,false);" fullword ascii
    $s5  = "var uWPIGFc = eZKjH(\"Sc nMrVdGZ r ZLNvmzPpg ipting MgYNkJx ULf ile RUYIZDAlpsTXjK System kR jYSLz Obj aEYABW ect yzrfhOU gzFPF" ascii
    $s6  = "var kkC = (\"2.XMLHTTP RcsvqWb PqKRN XML ream St UFrtkvZJ AD FoadaRa O POBE D\").split(\" \");" fullword ascii
    $s7  = "function uCri(TesRa) {" fullword ascii
    $s8  = "return UHwgMMP" fullword ascii
    $s9  = "function bhFl(EGvQn,EJDCQ,xxrKe) {" fullword ascii
    $s10 = "return new ActiveXObject(VNbZRM);" fullword ascii
    $s11 = "function pUWCDsMa(zKe) {" fullword ascii
    $s12 = "function ynLj(KQHtg,UswVF) {" fullword ascii
    $s13 = "return zFts.responseBody;" fullword ascii
    $s14 = "return LAPno;" fullword ascii
    $s15 = "return drmq.ExpandEnvironmentStrings(kckIQ);" fullword ascii
    $s16 = "function yfpiTIyfJ(lVWbrWyffDO) {" fullword ascii
    $s17 = "function fmND(dnPba,RZXjO) {" fullword ascii
    $s18 = "function wAoehyP(drmq,kckIQ) {" fullword ascii
    $s19 = "function tMgO(aurMT) {" fullword ascii
    $s20 = "function UVWn(HEDyi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}