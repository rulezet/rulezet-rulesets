rule sig_20160405_de18ec94c3d4e4326e3f1c8275be21dd {
  meta:
    description = "datamaliciousorder - file 20160405_de18ec94c3d4e4326e3f1c8275be21dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15527eb97648132499eaa7cc502168141c85b0de95d40e7500558080565d1d0e"

  strings:
    $s1  = "var lIxWYZt = \"dslBZJ*raT*pt.S\"+\"hell*xaxtVbb*Scri*\";" fullword ascii
    $s2  = "var GU = true  , HPva = fgB[7] + fgB[9] + fgB[11];" fullword ascii
    $s3  = "return FxCpwWX[0] + FxCpwWX[2] + FxCpwWX[4] + \".F\" + FxCpwWX[7] + FxCpwWX[9] + FxCpwWX[12] + FxCpwWX[14];" fullword ascii
    $s4  = "yuit.open(gQwFa,QhrHi,false);" fullword ascii
    $s5  = "var fgB = (\"2.XMLHTTP YdQHHry jRFtw XML ream St EFjIfnkS AD UfbpJTo O mRnW D\").split(\" \");" fullword ascii
    $s6  = "if(Z>=o.length) {break;}" fullword ascii
    $s7  = "return ChBAW;" fullword ascii
    $s8  = "function FgvQ(PBZhk) {" fullword ascii
    $s9  = "function CxQN(MrzTG) {" fullword ascii
    $s10 = "function eIiLM(rXE,cFicK) {" fullword ascii
    $s11 = "return rXE.split(cFicK);" fullword ascii
    $s12 = "function QbkIBfwe(FYr) {" fullword ascii
    $s13 = "function XBdQuKz(jQFo) {" fullword ascii
    $s14 = "function HAHZ(bvsJk) {" fullword ascii
    $s15 = "function HZxv(ClTMI) {" fullword ascii
    $s16 = "function KfmVB(NSKBkN) {" fullword ascii
    $s17 = "if (MrzTG == 985-785){return true;} else {return false;}" fullword ascii
    $s18 = "return \"rcosAgIsAHjjGF\";" fullword ascii
    $s19 = "return new ActiveXObject(kuFz);" fullword ascii
    $s20 = "function cYyp(UkzeY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}