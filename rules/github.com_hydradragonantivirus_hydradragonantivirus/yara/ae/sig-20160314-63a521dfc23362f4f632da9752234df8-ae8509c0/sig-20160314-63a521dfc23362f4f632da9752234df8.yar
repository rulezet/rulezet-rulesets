rule sig_20160314_63a521dfc23362f4f632da9752234df8 {
  meta:
    description = "datamaliciousorder - file 20160314_63a521dfc23362f4f632da9752234df8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ced699fe9793aef63729712af4095c0fb5326cbd6d203eef18bd31bf73512a4e"

  strings:
    $s1  = "var BdeLJXT = \"Sc aCqbxlD r eLaJgtniZ ipting WicdVpc vmo ile mByBofsdRCIieX System YP YifYb Obj ExwIrT ect hBwWbST wjuMs\".spli" ascii
    $s2  = "var BdeLJXT = \"Sc aCqbxlD r eLaJgtniZ ipting WicdVpc vmo ile mByBofsdRCIieX System YP YifYb Obj ExwIrT ect hBwWbST wjuMs\".spli" ascii
    $s3  = "return BdeLJXT[0] + BdeLJXT[2] + BdeLJXT[4] + \".F\" + BdeLJXT[7] + BdeLJXT[9] + BdeLJXT[12] + BdeLJXT[14];" fullword ascii
    $s4  = "var As = true  , pxmm = oOg[7] + oOg[9] + oOg[11];" fullword ascii
    $s5  = "KKXVh.open(XjeMM,SQfJk,false);" fullword ascii
    $s6  = "var oOg = (\"2.XMLHTTP OItxqtR xGzKA XML ream St MDIMrXab AD eWFexrH O wQwV D\").split(\" \");" fullword ascii
    $s7  = "function eZov(tTmZH) {" fullword ascii
    $s8  = "function WJVKW(bVCTnw) {" fullword ascii
    $s9  = "return OjIMEmm(AJ,iijbz[491-485]+iijbz[851-844]+iijbz[967-959]);" fullword ascii
    $s10 = "function DUSsDTBoa() {" fullword ascii
    $s11 = "function cQDd(PMFpM,kMeIZ) {" fullword ascii
    $s12 = "function QRpI(nauhu) {" fullword ascii
    $s13 = "return bVCTnw.position=647-647;" fullword ascii
    $s14 = "if (qPWeD == 481-281){return true;} else {return false;}" fullword ascii
    $s15 = "function HrQV(aUBUR) {" fullword ascii
    $s16 = "function bVLtl(VEprkZ) {" fullword ascii
    $s17 = "function fSfABUMA(pdG) {" fullword ascii
    $s18 = "if(e>=C.length) {break;}" fullword ascii
    $s19 = "return new ActiveXObject(VEprkZ);" fullword ascii
    $s20 = "function JuTR(KKXVh,SQfJk,XjeMM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}