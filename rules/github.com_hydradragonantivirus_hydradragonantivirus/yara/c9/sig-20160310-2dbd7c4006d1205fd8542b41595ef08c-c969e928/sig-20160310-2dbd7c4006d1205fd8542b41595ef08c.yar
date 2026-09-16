rule sig_20160310_2dbd7c4006d1205fd8542b41595ef08c {
  meta:
    description = "datamaliciousorder - file 20160310_2dbd7c4006d1205fd8542b41595ef08c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe8acca6935f388d5aa442ba77342f15bfe4920c24f428beb3ad5056d394390"

  strings:
    $s1  = "var hS = true  , smlr = qnR[7] + qnR[9] + qnR[11];" fullword ascii
    $s2  = "return tLRLZae[0] + tLRLZae[2] + tLRLZae[4] + \".F\" + tLRLZae[7] + tLRLZae[9] + tLRLZae[12] + tLRLZae[14];" fullword ascii
    $s3  = "nYiXS.open(BZvVX,RVOaV,false);" fullword ascii
    $s4  = "var qnR = (\"2.XMLHTTP sdrbbOZ DShuo XML ream St wGzcJchS AD oXHFXIi O Ewsp D\").split(\" \");" fullword ascii
    $s5  = "if(K>=d.length) {break;}" fullword ascii
    $s6  = "return pQlVvIx" fullword ascii
    $s7  = "function yQsn(GaKJl,aGHPw) {" fullword ascii
    $s8  = "if (QOjrK == 680-480){return true;} else {return false;}" fullword ascii
    $s9  = "function tskW(qNcRq) {" fullword ascii
    $s10 = "function czCV(QOjrK) {" fullword ascii
    $s11 = "if (F >= kiJKZ.length) {break;}" fullword ascii
    $s12 = "function SYVp(UlntW) {" fullword ascii
    $s13 = "function fyUNB(nNWHXR) {" fullword ascii
    $s14 = "return fBxuPXL(DG,rppvR[830-824]+rppvR[950-943]+rppvR[383-375]);" fullword ascii
    $s15 = "function YBwN(XxKmM) {" fullword ascii
    $s16 = "function GprY(nYiXS,RVOaV,BZvVX) {" fullword ascii
    $s17 = "function uIadzffw() {" fullword ascii
    $s18 = "function RGaZ(OfUok) {" fullword ascii
    $s19 = "function wRmla(iRROAM) {" fullword ascii
    $s20 = "return nikl.ExpandEnvironmentStrings(rvDHe);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}