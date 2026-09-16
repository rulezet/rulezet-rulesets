rule sig_20160520_13e1422a28abf8a61b3f72c49a370ba8 {
  meta:
    description = "datamaliciousorder - file 20160520_13e1422a28abf8a61b3f72c49a370ba8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be2184fa750dc799b1704d0d27f0f9c49958526998d0c9630b0062a18c8c6a6e"

  strings:
    $s1  = "function BllcCgiY(SrnTC) {var cqLlZMXX=QuszrxARzB[2];for(var uqDsY=0;uqDsY<SrnTC;uqDsY++){wbAVU+=cqLlZMXX.charAt(Math.floor(Math" ascii
    $s2  = "function BllcCgiY(SrnTC) {var cqLlZMXX=QuszrxARzB[2];for(var uqDsY=0;uqDsY<SrnTC;uqDsY++){wbAVU+=cqLlZMXX.charAt(Math.floor(Math" ascii
    $s3  = "function RXtQGWQwh(cAQrUknJC,eHiFTpl,jQdRSGpz){" fullword ascii
    $s4  = "function SRASn(GQIXKowa,pLhcfA,niuyMWRXe){ITxpb=GQIXKowa.split(niuyMWRXe);jyJANkN = QuszrxARzB[13];for(yIPlrFsH=0;yIPlrFsH<pLhcf" ascii
    $s5  = "A.length;yIPlrFsH++) {jyJANkN+=ITxpb[pLhcfA[yIPlrFsH]];}return jyJANkN.substring(3,jyJANkN.length);}" fullword ascii
    $s6  = "function HWkC(FqqlyD,MNXbWmm){CUme = QuszrxARzB[11].split(QuszrxARzB[12]);MNXbWmm.open(CUme[0]+CUme[2]+CUme[3], FqqlyD, false);M" ascii
    $s7  = "try{RXtQGWQwh(wzwxl[zPRN], YWIDfME() + QuszrxARzB[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function VOhACp(ghYYzX){return ghYYzX.ExpandEnvironmentStrings(QuszrxARzB[10])}" fullword ascii
    $s9  = "function JPlMp(ghYYzX){return new ActiveXObject(ghYYzX);}" fullword ascii
    $s10 = ".random()*cqLlZMXX.length));}return wbAVU;}" fullword ascii
    $s11 = "function qDMIk(BQbWWUEM,HZWsa,ChYTCRrDwf){BQbWWUEM.open();BQbWWUEM.type = 1;BQbWWUEM.write(HZWsa);BQbWWUEM.position = 0;BQbWWUEM" ascii
    $s12 = "function SRASn(GQIXKowa,pLhcfA,niuyMWRXe){ITxpb=GQIXKowa.split(niuyMWRXe);jyJANkN = QuszrxARzB[13];for(yIPlrFsH=0;yIPlrFsH<pLhcf" ascii
    $s13 = "function qDMIk(BQbWWUEM,HZWsa,ChYTCRrDwf){BQbWWUEM.open();BQbWWUEM.type = 1;BQbWWUEM.write(HZWsa);BQbWWUEM.position = 0;BQbWWUEM" ascii
    $s14 = "function YWIDfME() {var sSyV=100000;var VKkUfF = 100;return Math.random()*(sSyV-VKkUfF)+VKkUfF;}" fullword ascii
    $s15 = "function HWkC(FqqlyD,MNXbWmm){CUme = QuszrxARzB[11].split(QuszrxARzB[12]);MNXbWmm.open(CUme[0]+CUme[2]+CUme[3], FqqlyD, false);M" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}