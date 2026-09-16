rule sig_20160310_83f4dfb71d74d1ec0cf1d49fdb2cbc29 {
  meta:
    description = "datamaliciousorder - file 20160310_83f4dfb71d74d1ec0cf1d49fdb2cbc29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb24834e1510ee9bdb3e831eedb6e994dba85337586ba9de7128a9d31f262d8"

  strings:
    $s1  = "var Tz = true  , oiBr = zdu[7] + zdu[9] + zdu[11];" fullword ascii
    $s2  = "return yspPUCY[0] + yspPUCY[2] + yspPUCY[4] + \".F\" + yspPUCY[7] + yspPUCY[9] + yspPUCY[12] + yspPUCY[14];" fullword ascii
    $s3  = "var yspPUCY = \"Sc WPDTorm r ZPkhMwjuN ipting CpfeOyF usv ile aGlKaFFUDjsRvK System aD etxvg Obj oAuDzf ect LjjCosp\".split(\" " ascii
    $s4  = "var zdu = (\"2.XMLHTTP zdnoXSo nrsVF XML ream St qOxtHDFJ AD GxdneoG O nCTo D\").split(\" \");" fullword ascii
    $s5  = "return CHIowCj" fullword ascii
    $s6  = "function ReKf(GjEiB) {" fullword ascii
    $s7  = "return new ActiveXObject(hsCjSV);" fullword ascii
    $s8  = "function ICIghKnj(wWo) {" fullword ascii
    $s9  = "QSG = n; break; " fullword ascii
    $s10 = "function RjuirFvE() {" fullword ascii
    $s11 = "function PDVo(zKqYo) {" fullword ascii
    $s12 = "return yDyM.ExpandEnvironmentStrings(MnPJO);" fullword ascii
    $s13 = "function TDEsKFmIF(HRBUf,TCRmg,EIjSx,olKS) {" fullword ascii
    $s14 = "function dAEa(zovGv,lqZTB) {" fullword ascii
    $s15 = "function yEqWj(gHqjwn) {" fullword ascii
    $s16 = "if (GjEiB == 748-548){return true;} else {return false;}" fullword ascii
    $s17 = "return MryPN.status;" fullword ascii
    $s18 = "function sVOI(MryPN) {" fullword ascii
    $s19 = "function LWARnEc(gDRO) {" fullword ascii
    $s20 = "function VhYvwvBjp(VZitlBNmROk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}