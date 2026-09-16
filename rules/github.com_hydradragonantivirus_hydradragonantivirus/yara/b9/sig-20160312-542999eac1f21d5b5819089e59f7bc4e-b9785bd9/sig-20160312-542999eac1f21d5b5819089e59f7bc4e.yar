rule sig_20160312_542999eac1f21d5b5819089e59f7bc4e {
  meta:
    description = "datamaliciousorder - file 20160312_542999eac1f21d5b5819089e59f7bc4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95abda1c9f1fa29067552ba6f06dd53e79bd275cbb3334638865b34adc7d1af2"

  strings:
    $s1  = "var FZ = true  , flmd = Zeh[7] + Zeh[9] + Zeh[11];" fullword ascii
    $s2  = "return qyNLyFZ[0] + qyNLyFZ[2] + qyNLyFZ[4] + \".F\" + qyNLyFZ[7] + qyNLyFZ[9] + qyNLyFZ[12] + qyNLyFZ[14];" fullword ascii
    $s3  = "var Zeh = (\"2.XMLHTTP wFrMhmV TRIUX XML ream St AkVAACVj AD khGgEla O TiCN D\").split(\" \");" fullword ascii
    $s4  = "var qyNLyFZ = \"Sc lIxSQlX r iohUvQeSE ipting QJnSOGS tLL ile SPuGLegMPVAitq System ce SAgyz Obj XQMWqh ect PPzevYt\".split(\" " ascii
    $s5  = "psbRC.open(IADcU,ttApe,false);" fullword ascii
    $s6  = "if (Mbbcj > 138491-482){return true;} else {return false;}" fullword ascii
    $s7  = "function tXqgDuXs(WqU) {" fullword ascii
    $s8  = "function aQuh(AbuBh,HuhjR) {" fullword ascii
    $s9  = "if (JDrFT == 475-275){return true;} else {return false;}" fullword ascii
    $s10 = "return new ActiveXObject(UBXqjB);" fullword ascii
    $s11 = "return SzkhL.status;" fullword ascii
    $s12 = "return fMiB.ExpandEnvironmentStrings(kosOl);" fullword ascii
    $s13 = "if(O>=F.length) {break;}" fullword ascii
    $s14 = "return EvKo.responseBody;" fullword ascii
    $s15 = "function rMano(qiDyVp) {" fullword ascii
    $s16 = "function wEwS(xoVsy) {" fullword ascii
    $s17 = "return WqU.size;" fullword ascii
    $s18 = "function wRqEOjEs() {" fullword ascii
    $s19 = "function qmZp(SzkhL) {" fullword ascii
    $s20 = "function RKUzMOpM(vyZkm,CKRYwt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}