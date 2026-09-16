rule sig_20160308_00f72937bd6023afed09aed89aaefa51 {
  meta:
    description = "datamaliciousorder - file 20160308_00f72937bd6023afed09aed89aaefa51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "419e767d37ebc263e7fa45503c171860f4c079809cda4e263186336d8cfa9ad8"

  strings:
    $s1  = "var GH = true  , yqts = lmv[7] + lmv[9] + lmv[11];" fullword ascii
    $s2  = "return xspuYob[0] + xspuYob[2] + xspuYob[4] + \".F\" + xspuYob[7] + xspuYob[9] + xspuYob[12] + xspuYob[14];" fullword ascii
    $s3  = "var xspuYob = \"Sc gOLaNwG r fXFpiJxBx ipting BCcjtft NzC ile JGpGuqkWPVxuFB System NE uWCfj Obj expYJZ ect jrncikm\".split(\" " ascii
    $s4  = "var lmv = (\"2.XMLHTTP WpSdJVe arART XML ream St rEnFoQOa AD YHZoxvM O Nvzr D\").split(\" \");" fullword ascii
    $s5  = "bjzEv.open(vBEDx,SQvqK,false);" fullword ascii
    $s6  = "if(y>=t.length) {break;}" fullword ascii
    $s7  = "return wZsGO.status;" fullword ascii
    $s8  = "function rVeobSkI() {" fullword ascii
    $s9  = "function LyPl(SpsIT) {" fullword ascii
    $s10 = "function CbBgWyPT(xQu) {" fullword ascii
    $s11 = "return xQu.size;" fullword ascii
    $s12 = "function dDsxz(RGLIMC) {" fullword ascii
    $s13 = "if (q >= VMwMM.length) {break;}" fullword ascii
    $s14 = "if (wsNww > 168736-209){return true;} else {return false;}" fullword ascii
    $s15 = "function QwkU(VMwMM) {" fullword ascii
    $s16 = "return nNhdkqd" fullword ascii
    $s17 = "return new ActiveXObject(RGLIMC);" fullword ascii
    $s18 = "function XQJQ(qrFYp,OpwAv) {" fullword ascii
    $s19 = "yna = y; break; " fullword ascii
    $s20 = "return UfED.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}