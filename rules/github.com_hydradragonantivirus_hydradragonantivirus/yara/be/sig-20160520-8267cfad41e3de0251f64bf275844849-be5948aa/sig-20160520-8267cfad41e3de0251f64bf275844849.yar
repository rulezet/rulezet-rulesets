rule sig_20160520_8267cfad41e3de0251f64bf275844849 {
  meta:
    description = "datamaliciousorder - file 20160520_8267cfad41e3de0251f64bf275844849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fedafea4e0fec959a04264ea09a3a03fac2dde94bfa12c1c0a3955693e4cefe4"

  strings:
    $s1  = "function QchWctGM(aJkLP) {var jLQZFzAK=QhVpvSxZ[2];for(var juNzF=0;juNzF<aJkLP;juNzF++){Mbzfu+=jLQZFzAK.charAt(Math.floor(Math.r" ascii
    $s2  = "function QchWctGM(aJkLP) {var jLQZFzAK=QhVpvSxZ[2];for(var juNzF=0;juNzF<aJkLP;juNzF++){Mbzfu+=jLQZFzAK.charAt(Math.floor(Math.r" ascii
    $s3  = "function UvizA(FbjSPZba,jTZEyb,DIVpJRlaR){uXUIU=FbjSPZba.split(DIVpJRlaR);TUGYMDx = QhVpvSxZ[13];for(kEcZsNLF=0;kEcZsNLF<jTZEyb." ascii
    $s4  = "length;kEcZsNLF++) {TUGYMDx+=uXUIU[jTZEyb[kEcZsNLF]];}return TUGYMDx.substring(3,TUGYMDx.length);}" fullword ascii
    $s5  = "function dWKzmdNgq(NMwoGvNEN,XWjLgrD,HfPLeGHd){" fullword ascii
    $s6  = "function QELri(RKXYQA){return new ActiveXObject(RKXYQA);}" fullword ascii
    $s7  = "function ytMZTV(RKXYQA){return RKXYQA.ExpandEnvironmentStrings(QhVpvSxZ[10])}" fullword ascii
    $s8  = "function Zqxz(QXualu,QRWYlbh){CDjE = QhVpvSxZ[11].split(QhVpvSxZ[12]);QRWYlbh.open(CDjE[0]+CDjE[2]+CDjE[3], QXualu, false);QRWYl" ascii
    $s9  = "function WyyZS(gcgqiRUC,wQUnp,xkJEKwAHcI){gcgqiRUC.open();gcgqiRUC.type = 1;gcgqiRUC.write(wQUnp);gcgqiRUC.position = 0;gcgqiRUC" ascii
    $s10 = "function mMJGqao() {var lkHY=100000;var BtKYtP = 100;return Math.random()*(lkHY-BtKYtP)+BtKYtP;}" fullword ascii
    $s11 = "function Zqxz(QXualu,QRWYlbh){CDjE = QhVpvSxZ[11].split(QhVpvSxZ[12]);QRWYlbh.open(CDjE[0]+CDjE[2]+CDjE[3], QXualu, false);QRWYl" ascii
    $s12 = "function UvizA(FbjSPZba,jTZEyb,DIVpJRlaR){uXUIU=FbjSPZba.split(DIVpJRlaR);TUGYMDx = QhVpvSxZ[13];for(kEcZsNLF=0;kEcZsNLF<jTZEyb." ascii
    $s13 = "function WyyZS(gcgqiRUC,wQUnp,xkJEKwAHcI){gcgqiRUC.open();gcgqiRUC.type = 1;gcgqiRUC.write(wQUnp);gcgqiRUC.position = 0;gcgqiRUC" ascii
    $s14 = "try{dWKzmdNgq(JZkzu[rsli], mMJGqao() + QhVpvSxZ[9], 1)}catch(e){}; " fullword ascii
    $s15 = "andom()*jLQZFzAK.length));}return Mbzfu;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}