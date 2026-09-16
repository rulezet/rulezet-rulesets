rule sig_20160307_736f3e58981ddc67d204fd77c6169fd0 {
  meta:
    description = "datamaliciousorder - file 20160307_736f3e58981ddc67d204fd77c6169fd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "944026b0e7eec7cd11ff76281ad3ec983f4d9eec12ec24b85ed2acd80bc7fefb"

  strings:
    $s1  = "return pziVqzo[0] + pziVqzo[2] + pziVqzo[4] + \".F\" + pziVqzo[7] + pziVqzo[9] + pziVqzo[12] + pziVqzo[14];" fullword ascii
    $s2  = "var sR = true  , PsnD = fJN[7] + fJN[9] + fJN[11];" fullword ascii
    $s3  = "Vmoxg.open(zMzfY,HUjfC,false);" fullword ascii
    $s4  = "var fJN = (\"2.XMLHTTP SGKxwgL KuRgr XML ream St rvMpAfIc AD XjZnYbT O fePo D\").split(\" \");" fullword ascii
    $s5  = "var pziVqzo = \"Sc oMiCLWB r BnYAfJBFP ipting GIjwtET XpF ile lGwjvSZSPRcgmR System ef xTSNY Obj liaQHh ect VXTlMmU\".split(\" " ascii
    $s6  = "function GRrwPfFGX(iMOBRstifyg) {" fullword ascii
    $s7  = "return new ActiveXObject(gFgCjJ);" fullword ascii
    $s8  = "function sGWEUAlhB(ysahX,csIwG,kzDVp,ifyf) {" fullword ascii
    $s9  = "function tNzW(aozxk) {" fullword ascii
    $s10 = "return fahej;" fullword ascii
    $s11 = "return CD.ExpandEnvironmentStrings(eqxHd[6]+eqxHd[7]+eqxHd[8]);" fullword ascii
    $s12 = "function HrPu(NyzOM) {" fullword ascii
    $s13 = "if (aozxk > 184235-314){return true;} else {return false;}" fullword ascii
    $s14 = "if (S >= KKjCd.length) {break;}" fullword ascii
    $s15 = "return KzTq.responseBody;" fullword ascii
    $s16 = "if (UZiRM == 1012-812){return true;} else {return false;}" fullword ascii
    $s17 = "function uTMz(KKjCd) {" fullword ascii
    $s18 = "function brVAFGze() {" fullword ascii
    $s19 = "function iqzt(rEdLu,VHAMZ) {" fullword ascii
    $s20 = "return pDE.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}