rule sig_20160419_f0f5e6a6aea23fe60f1f39ebdbd1a8bd {
  meta:
    description = "datamaliciousorder - file 20160419_f0f5e6a6aea23fe60f1f39ebdbd1a8bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93b4a3920cbf5bcfa9c7f6a336c7433340ffaa4455bf7a958d44d1614f31676c"

  strings:
    $s1  = "return WzGMHef[0] + WzGMHef[2] + WzGMHef[4] + \".F\" + WzGMHef[7] + WzGMHef[9] + WzGMHef[12] + WzGMHef[14];" fullword ascii
    $s2  = "var ae = true  , Nskd = KxT[7] + KxT[9] + KxT[11];" fullword ascii
    $s3  = "PUTM.open(zHXCo,OhiHp,false);" fullword ascii
    $s4  = "var KxT = (\"2.XMLHTTP HmEjYZa yOzJc XML ream St dzRoUBZH AD rrylDSR O xijV D\").split(\" \");" fullword ascii
    $s5  = "function OjsLlLGMe(eXsbs) {" fullword ascii
    $s6  = "function YTkG(ptkYw) {" fullword ascii
    $s7  = "function AwhY(TCxos,yHunm) {" fullword ascii
    $s8  = "function WVJYQ(ooxOGN) {" fullword ascii
    $s9  = "function tdLz(KPceH) {" fullword ascii
    $s10 = "if (ptkYw != 643-443){return false;} else {return true;}" fullword ascii
    $s11 = "function zosazTbA(iNm) {" fullword ascii
    $s12 = "function EYPO(cqsZD) {" fullword ascii
    $s13 = "if (aKwWr > 154688-594){return true;} else {return false;}" fullword ascii
    $s14 = "function OTXNBjg(Xbhg,HIqBb) {" fullword ascii
    $s15 = "function Soey(aKwWr) {" fullword ascii
    $s16 = "function PEwfqR(glOQ,JpRvxD) {" fullword ascii
    $s17 = "return dRBUOQf[0];" fullword ascii
    $s18 = "function puJLPcr(tSdK) {" fullword ascii
    $s19 = "function mVMo(lntgI,VIgdu) {" fullword ascii
    $s20 = "function QQkE(vQWUJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}