rule sig_20160321_9e7416280b3f6b19747db4e341502cd8 {
  meta:
    description = "datamaliciousorder - file 20160321_9e7416280b3f6b19747db4e341502cd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b91ad3221c0a65f0c18b719a0c2431dfd3561489e46a6857d3dfbd6a36e54a3"

  strings:
    $s1  = "return WScript.CreateObject(dxcBW);" fullword ascii
    $s2  = "var co = true  , ERrx = cOx[7] + cOx[9] + cOx[11];" fullword ascii
    $s3  = "return rRKKhuZ[0] + rRKKhuZ[2] + rRKKhuZ[4] + \".F\" + rRKKhuZ[7] + rRKKhuZ[9] + rRKKhuZ[12] + rRKKhuZ[14];" fullword ascii
    $s4  = "SsxYM.open(emrSb,VSiau,false);" fullword ascii
    $s5  = "var rRKKhuZ = gjAcc(IjAOSJBVdS+\" \"+\"System iX ZUVGN Obj gIWVQy ect iilHVem juEbG\", \" \");" fullword ascii
    $s6  = "var cOx = (\"2.XMLHTTP SLsSNJU MIuLK XML ream St WblXcNrR AD PEBtVCJ O dnbZ D\").split(\" \");" fullword ascii
    $s7  = "function gjAcc(fYs,zTLFR) {" fullword ascii
    $s8  = "return fYs.split(zTLFR);" fullword ascii
    $s9  = "function uMXX(hVoMD) {" fullword ascii
    $s10 = "function bzCzQkNU(UOBx) {" fullword ascii
    $s11 = "return UNnU.ExpandEnvironmentStrings(JhjOD);" fullword ascii
    $s12 = "function zHYVC(bKisyC) {" fullword ascii
    $s13 = "function WFPzvPBgn(QvCxm) {" fullword ascii
    $s14 = "return yVvlZnY(qj,LlklM[931-925]+LlklM[623-616]+LlklM[608-600]);" fullword ascii
    $s15 = "function xmCX(lhdbg) {" fullword ascii
    $s16 = "function QEhi(qXtYA,JStGp) {" fullword ascii
    $s17 = "function IDcnWgW(KZUE) {" fullword ascii
    $s18 = "if (hVoMD > 186954-107){return true;} else {return false;}" fullword ascii
    $s19 = "if(i>=B.length) {break;}" fullword ascii
    $s20 = "lWh = i; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}