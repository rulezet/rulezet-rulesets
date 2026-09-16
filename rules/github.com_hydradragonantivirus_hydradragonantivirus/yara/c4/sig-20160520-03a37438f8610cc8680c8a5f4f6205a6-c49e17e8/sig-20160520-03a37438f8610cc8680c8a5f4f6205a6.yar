rule sig_20160520_03a37438f8610cc8680c8a5f4f6205a6 {
  meta:
    description = "datamaliciousorder - file 20160520_03a37438f8610cc8680c8a5f4f6205a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be29b18fd31a7bc3d15d12a3c14a50248bf39457d5dabe66617a5760cd584750"

  strings:
    $s1  = "function AJIxrrGS(Eebwk) {var yECHGCbV=iLtkmGVzeqjPeONNmEd[2];for(var gFkxd=0;gFkxd<Eebwk;gFkxd++){aWndw+=yECHGCbV.charAt(Math.f" ascii
    $s2  = "function AJIxrrGS(Eebwk) {var yECHGCbV=iLtkmGVzeqjPeONNmEd[2];for(var gFkxd=0;gFkxd<Eebwk;gFkxd++){aWndw+=yECHGCbV.charAt(Math.f" ascii
    $s3  = "function AtLE(JaqMbU,vybdkGI){jvDu = iLtkmGVzeqjPeONNmEd[11].split(iLtkmGVzeqjPeONNmEd[12]);vybdkGI.open(jvDu[0]+jvDu[2]+jvDu[3]" ascii
    $s4  = "try{OMAwRqx=WXaQupIKO(kzzEC[Hiwt], crqAlmH() + iLtkmGVzeqjPeONNmEd[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function oXOkS(TBXJtP){return new ActiveXObject(TBXJtP);}" fullword ascii
    $s6  = "FTK<RylynO.length;ruSWiFTK++) {UokeuqT+=VXqtX[RylynO[ruSWiFTK]];}return UokeuqT.substring(3,UokeuqT.length);}" fullword ascii
    $s7  = ", JaqMbU, false);vybdkGI.send();}" fullword ascii
    $s8  = "function crqAlmH() {var SsIJ=100000;var NpFZXt = 100;return Math.random()*(SsIJ-NpFZXt)+NpFZXt;}" fullword ascii
    $s9  = "AtLE(kyZnwgSgX,bdUoK);" fullword ascii
    $s10 = "function ioFZi(YXJdmncR,ImwWs,fKsTDiDsTI){YXJdmncR.open();YXJdmncR.type = 1;YXJdmncR.write(ImwWs);YXJdmncR.position = 0;YXJdmncR" ascii
    $s11 = "if (OMAwRqx==0) break;" fullword ascii
    $s12 = "function GUpaE(tdxdKEpV,RylynO,zEWhPEqGt){VXqtX=tdxdKEpV.split(zEWhPEqGt);UokeuqT = iLtkmGVzeqjPeONNmEd[13];for(ruSWiFTK=0;ruSWi" ascii
    $s13 = "function WXaQupIKO(kyZnwgSgX,OAPgUcz,PxcUpVGn){" fullword ascii
    $s14 = "function AtLE(JaqMbU,vybdkGI){jvDu = iLtkmGVzeqjPeONNmEd[11].split(iLtkmGVzeqjPeONNmEd[12]);vybdkGI.open(jvDu[0]+jvDu[2]+jvDu[3]" ascii
    $s15 = "function ioFZi(YXJdmncR,ImwWs,fKsTDiDsTI){YXJdmncR.open();YXJdmncR.type = 1;YXJdmncR.write(ImwWs);YXJdmncR.position = 0;YXJdmncR" ascii
    $s16 = "loor(Math.random()*yECHGCbV.length));}return aWndw;}" fullword ascii
    $s17 = "function GUpaE(tdxdKEpV,RylynO,zEWhPEqGt){VXqtX=tdxdKEpV.split(zEWhPEqGt);UokeuqT = iLtkmGVzeqjPeONNmEd[13];for(ruSWiFTK=0;ruSWi" ascii
    $s18 = "function QHwhDd(TBXJtP){return TBXJtP.ExpandEnvironmentStrings(iLtkmGVzeqjPeONNmEd[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}