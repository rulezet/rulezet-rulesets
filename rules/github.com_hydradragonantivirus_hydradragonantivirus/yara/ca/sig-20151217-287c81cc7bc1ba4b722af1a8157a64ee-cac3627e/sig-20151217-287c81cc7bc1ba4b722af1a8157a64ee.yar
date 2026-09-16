rule sig_20151217_287c81cc7bc1ba4b722af1a8157a64ee {
  meta:
    description = "datamaliciousorder - file 20151217_287c81cc7bc1ba4b722af1a8157a64ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b32cfc3283117c66625cf3cf0e35c867f5cb7349ec474b4b60b758352975766"

  strings:
    $s1  = "function tmRSiXpsKfPPvSLjD(sNSPr){rWaeLJnVaEF= '';PdPYYrTKCMA=Math.round((Math.pow(Math.sin(906), 2) + Math.pow(Math.cos(906), 2" ascii
    $s2  = "w(Math.cos(929), 2) - 1)));} oyfcPynhN[PdPYYrTKCMA]++;}PdPYYrTKCMA++;} return rWaeLJnVaEF}" fullword ascii
    $s3  = "th.pow(Math.cos(189), 2) - 1)); while(true) { if(oyfcPynhN[PdPYYrTKCMA] > sNSPr[PdPYYrTKCMA].length-(410+140)/550) { break; } if" ascii
    $s4  = ") - 1));while(true){if (PdPYYrTKCMA >= (4545+489)/839){break;}oyfcPynhN[PdPYYrTKCMA]=Math.round((Math.pow(Math.sin(189), 2) + Ma" ascii
    $s5  = "function tmRSiXpsKfPPvSLjD(sNSPr){rWaeLJnVaEF= '';PdPYYrTKCMA=Math.round((Math.pow(Math.sin(906), 2) + Math.pow(Math.cos(906), 2" ascii
    $s6  = "function GKFSRTM(zAeVZUKJhjJFCqqXZPImPaAbckKrVkRZbsZM) {return !RuOagFjxsTX(zwOIVcgzcijogcR(zAeVZUKJhjJFCqqXZPImPaAbckKrVkRZbsZM" ascii
    $s7  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s8  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s9  = "function PuSjb(AJhAwjUNNWh,jjBVkrfjbJnkA,IQPSBXZT){OdRV=GSpvUgKtSkCqykjcH(AJhAwjUNNWh,jjBVkrfjbJnkA);VGoBl=OdRV.toString(IQPSBXZ" ascii
    $s10 = "function GKFSRTM(zAeVZUKJhjJFCqqXZPImPaAbckKrVkRZbsZM) {return !RuOagFjxsTX(zwOIVcgzcijogcR(zAeVZUKJhjJFCqqXZPImPaAbckKrVkRZbsZM" ascii
    $s11 = "function kvkHaUhYhuFt(DxppzQBKEzbvd) {return isFinite(DxppzQBKEzbvd);}" fullword ascii
    $s12 = "function cnMBGRvcqyTlzBZZGjKXzKQuiWcXCzWPGCfvTSCBWHpGBJPtyBiSRe(iTNnzMkvHWiOW,PwTHJgKiCPcLYX){ return otmXOfB[haVomIwn[PuSjb(iTN" ascii
    $s13 = "function J(mVFQtlDDIVCqCe,uBTYBFywhBwpi,aRRZTlGhAeB) {mVFQtlDDIVCqCe[uBTYBFywhBwpi]=aRRZTlGhAeB;}" fullword ascii
    $s14 = "function cnMBGRvcqyTlzBZZGjKXzKQuiWcXCzWPGCfvTSCBWHpGBJPtyBiSRe(iTNnzMkvHWiOW,PwTHJgKiCPcLYX){ return otmXOfB[haVomIwn[PuSjb(iTN" ascii
    $s15 = "function RuOagFjxsTX(mIlUKDINxQrwjO) {return isNaN(mIlUKDINxQrwjO);}" fullword ascii
    $s16 = "T);return VGoBl;}" fullword ascii
    $s17 = "function zwOIVcgzcijogcR(rcxuVdRbYPNjFLoWsrW) {return parseFloat(rcxuVdRbYPNjFLoWsrW);}" fullword ascii
    $s18 = "function PuSjb(AJhAwjUNNWh,jjBVkrfjbJnkA,IQPSBXZT){OdRV=GSpvUgKtSkCqykjcH(AJhAwjUNNWh,jjBVkrfjbJnkA);VGoBl=OdRV.toString(IQPSBXZ" ascii
    $s19 = "function GSpvUgKtSkCqykjcH(jUMRnQlcWf,rvgwbKFivZ) {return parseInt(jUMRnQlcWf,rvgwbKFivZ);}" fullword ascii
    $s20 = "function F(OVVMeMRYwFSw,eGXMtlXketcVyI){OVVMeMRYwFSw.push(eGXMtlXketcVyI);}" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}