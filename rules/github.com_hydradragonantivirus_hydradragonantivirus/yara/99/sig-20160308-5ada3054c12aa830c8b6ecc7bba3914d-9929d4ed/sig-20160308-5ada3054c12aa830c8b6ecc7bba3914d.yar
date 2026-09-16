rule sig_20160308_5ada3054c12aa830c8b6ecc7bba3914d {
  meta:
    description = "datamaliciousorder - file 20160308_5ada3054c12aa830c8b6ecc7bba3914d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095611cd10609cfc5ca251f866e339e71c552c73f3bc18381304746e03088bd4"

  strings:
    $s1  = "var qS = true  , stHT = QDF[7] + QDF[9] + QDF[11];" fullword ascii
    $s2  = "return bgXKtun[0] + bgXKtun[2] + bgXKtun[4] + \".F\" + bgXKtun[7] + bgXKtun[9] + bgXKtun[12] + bgXKtun[14];" fullword ascii
    $s3  = "var QDF = (\"2.XMLHTTP CxHEiXf hKWyf XML ream St poHfYkCC AD PFOZtdf O uHbK D\").split(\" \");" fullword ascii
    $s4  = "IRrWQ.open(HqsbC,NJRGK,false);" fullword ascii
    $s5  = "var bgXKtun = \"Sc gMJGsNP r dQqdjMLYH ipting fGMYtcj zFf ile LbEVUVhDuyqXYi System Aj Wosuf Obj foSHXK ect SvDLyLD\".split(\" " ascii
    $s6  = "return lR.ExpandEnvironmentStrings(AmvQh[6]+AmvQh[7]+AmvQh[8]);" fullword ascii
    $s7  = "function jrlJcdg(HgPg) {" fullword ascii
    $s8  = "function mlslVgLEd(CFOmo,nykcJ,bHXDq,uNHe) {" fullword ascii
    $s9  = "function tgFCmauS() {" fullword ascii
    $s10 = "function LWyr(BrlSP) {" fullword ascii
    $s11 = "return vRqzWTq" fullword ascii
    $s12 = "function vZXA(qEZZr,QGBnF) {" fullword ascii
    $s13 = "function NMaH(IRrWQ,NJRGK,HqsbC) {" fullword ascii
    $s14 = "function KlFsFcw(WODE) {" fullword ascii
    $s15 = "if (BrlSP > 160846-671){return true;} else {return false;}" fullword ascii
    $s16 = "function QUsy(hMJOZ) {" fullword ascii
    $s17 = "function prGMq(SFVWNh) {" fullword ascii
    $s18 = "function BXxKeLCnV(aGminuZZNbg) {" fullword ascii
    $s19 = "return khD.size;" fullword ascii
    $s20 = "if (vyXuk == 588-388){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}