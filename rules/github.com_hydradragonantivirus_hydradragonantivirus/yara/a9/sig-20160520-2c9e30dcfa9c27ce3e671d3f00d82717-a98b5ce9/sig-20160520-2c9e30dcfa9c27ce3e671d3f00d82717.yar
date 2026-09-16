rule sig_20160520_2c9e30dcfa9c27ce3e671d3f00d82717 {
  meta:
    description = "datamaliciousorder - file 20160520_2c9e30dcfa9c27ce3e671d3f00d82717.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0f95f67e5d57f91a883f51cae5192ce3341968059e1757ac1068bc151fe6fae"

  strings:
    $s1  = "function AUExVqan(FVvxR) {var yMGouzSj=ZqBGXpsCBOMknwpIPPqgFn[2];for(var yFNme=0;yFNme<FVvxR;yFNme++){CvKcq+=yMGouzSj.charAt(Mat" ascii
    $s2  = "function AUExVqan(FVvxR) {var yMGouzSj=ZqBGXpsCBOMknwpIPPqgFn[2];for(var yFNme=0;yFNme<FVvxR;yFNme++){CvKcq+=yMGouzSj.charAt(Mat" ascii
    $s3  = "if (pYspyVl==0) break;" fullword ascii
    $s4  = "try{pYspyVl=SiYIrefIX(brmta[lVpZ], rXlHHsA() + ZqBGXpsCBOMknwpIPPqgFn[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function nLNi(mJyhbK,VItfEPy){Nwid = ZqBGXpsCBOMknwpIPPqgFn[11].split(ZqBGXpsCBOMknwpIPPqgFn[12]);VItfEPy.open(Nwid[0]+Nwid[2]+N" ascii
    $s6  = "function nLNi(mJyhbK,VItfEPy){Nwid = ZqBGXpsCBOMknwpIPPqgFn[11].split(ZqBGXpsCBOMknwpIPPqgFn[12]);VItfEPy.open(Nwid[0]+Nwid[2]+N" ascii
    $s7  = "function rXlHHsA() {var UTkE=100000;var mfInHW = 100;return Math.random()*(UTkE-mfInHW)+mfInHW;}" fullword ascii
    $s8  = "function lEwzB(QbrHJecN,bDnFl,YavemXUYSg){QbrHJecN.open();QbrHJecN.type = 1;QbrHJecN.write(bDnFl);QbrHJecN.position = 0;QbrHJecN" ascii
    $s9  = "function sYWYV(dTjxuiPd,iGOrfF,FtxXnMUai){vBtPg=dTjxuiPd.split(FtxXnMUai);EKAISXt = ZqBGXpsCBOMknwpIPPqgFn[13];for(DHGrwygl=0;DH" ascii
    $s10 = "function TCsToQ(VIEKbQ){return VIEKbQ.ExpandEnvironmentStrings(ZqBGXpsCBOMknwpIPPqgFn[10])}" fullword ascii
    $s11 = "function SiYIrefIX(xSPjaiXNe,FlTnVXb,GoZjOxIP){" fullword ascii
    $s12 = "function sYWYV(dTjxuiPd,iGOrfF,FtxXnMUai){vBtPg=dTjxuiPd.split(FtxXnMUai);EKAISXt = ZqBGXpsCBOMknwpIPPqgFn[13];for(DHGrwygl=0;DH" ascii
    $s13 = "Grwygl<iGOrfF.length;DHGrwygl++) {EKAISXt+=vBtPg[iGOrfF[DHGrwygl]];}return EKAISXt.substring(3,EKAISXt.length);}" fullword ascii
    $s14 = "h.floor(Math.random()*yMGouzSj.length));}return CvKcq;}" fullword ascii
    $s15 = "wid[3], mJyhbK, false);VItfEPy.send();}" fullword ascii
    $s16 = "function lEwzB(QbrHJecN,bDnFl,YavemXUYSg){QbrHJecN.open();QbrHJecN.type = 1;QbrHJecN.write(bDnFl);QbrHJecN.position = 0;QbrHJecN" ascii
    $s17 = "function tOFxJ(VIEKbQ){return new ActiveXObject(VIEKbQ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}