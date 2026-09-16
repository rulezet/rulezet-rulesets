rule sig_20160311_a22a62a7a44e03f340a9d9e20732adb9 {
  meta:
    description = "datamaliciousorder - file 20160311_a22a62a7a44e03f340a9d9e20732adb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68fd2399128fd7c6e1ef40cdc87b3a917a2b6f1c3ff2c10b621004c1d3de0b0b"

  strings:
    $s1  = "var SP = true  , Tgdq = noJ[7] + noJ[9] + noJ[11];" fullword ascii
    $s2  = "return lxdRFbi[0] + lxdRFbi[2] + lxdRFbi[4] + \".F\" + lxdRFbi[7] + lxdRFbi[9] + lxdRFbi[12] + lxdRFbi[14];" fullword ascii
    $s3  = "var lxdRFbi = \"Sc BVUMKnV r CQezYqKpz ipting KWnYmuc kCz ile WzHLpuzazdtHyE System HA UTznU Obj rVlzNp ect sRUxrUi\".split(\" " ascii
    $s4  = "ypVuT.open(fSIod,IYdfz,false);" fullword ascii
    $s5  = "var noJ = (\"2.XMLHTTP sqJySTH mluyW XML ream St EwdGvzPc AD mTAUSov O lyxH D\").split(\" \");" fullword ascii
    $s6  = "function VsFJ(zcTZe) {" fullword ascii
    $s7  = "if (s >= vlZme.length) {break;}" fullword ascii
    $s8  = "return VyBvmj.position=107-107;" fullword ascii
    $s9  = "function lDwJ(ypVuT,IYdfz,fSIod) {" fullword ascii
    $s10 = "return jKAJ.ExpandEnvironmentStrings(CBeLP);" fullword ascii
    $s11 = "function mefbSPwlS() {" fullword ascii
    $s12 = "if(g>=f.length) {break;}" fullword ascii
    $s13 = "function vMIeVAFO() {" fullword ascii
    $s14 = "function YQXHFvYu(jsG) {" fullword ascii
    $s15 = "return jsG.size;" fullword ascii
    $s16 = "return gFkP.responseBody;" fullword ascii
    $s17 = "function VMhC(vvyqz) {" fullword ascii
    $s18 = "return GUfgz.status;" fullword ascii
    $s19 = "if (oqEDf > 121992-888){return true;} else {return false;}" fullword ascii
    $s20 = "function DBym(oqEDf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}