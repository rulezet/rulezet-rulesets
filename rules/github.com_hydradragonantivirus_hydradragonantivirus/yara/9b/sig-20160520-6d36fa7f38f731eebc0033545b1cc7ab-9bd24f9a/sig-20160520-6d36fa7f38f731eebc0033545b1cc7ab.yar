rule sig_20160520_6d36fa7f38f731eebc0033545b1cc7ab {
  meta:
    description = "datamaliciousorder - file 20160520_6d36fa7f38f731eebc0033545b1cc7ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6fde9ed813444ebd043c6e134f763c21a58fed494491b521cecccb028911795"

  strings:
    $s1  = "function EXsucqbi(nfcMQ) {var YPFRjeKT=IPIxPNxGcUAODIqUsCHHK[2];for(var wpBcW=0;wpBcW<nfcMQ;wpBcW++){lcXwm+=YPFRjeKT.charAt(Math" ascii
    $s2  = "function EXsucqbi(nfcMQ) {var YPFRjeKT=IPIxPNxGcUAODIqUsCHHK[2];for(var wpBcW=0;wpBcW<nfcMQ;wpBcW++){lcXwm+=YPFRjeKT.charAt(Math" ascii
    $s3  = "q[3], gbfRbq, false);weGctmH.send();}" fullword ascii
    $s4  = "function VOMvd(bXMjYbmY,VxYIL,kDWNKfcRYj){bXMjYbmY.open();bXMjYbmY.type = 1;bXMjYbmY.write(VxYIL);bXMjYbmY.position = 0;bXMjYbmY" ascii
    $s5  = "function NrwiiY(jIuVTj){return jIuVTj.ExpandEnvironmentStrings(IPIxPNxGcUAODIqUsCHHK[10])}" fullword ascii
    $s6  = "try{zPMuSwAMP(NDRKx[tZgs], qWwXDpx() + IPIxPNxGcUAODIqUsCHHK[9], 1)}catch(e){}; " fullword ascii
    $s7  = "function KpxU(gbfRbq,weGctmH){Cvvq = IPIxPNxGcUAODIqUsCHHK[11].split(IPIxPNxGcUAODIqUsCHHK[12]);weGctmH.open(Cvvq[0]+Cvvq[2]+Cvv" ascii
    $s8  = "function VOMvd(bXMjYbmY,VxYIL,kDWNKfcRYj){bXMjYbmY.open();bXMjYbmY.type = 1;bXMjYbmY.write(VxYIL);bXMjYbmY.position = 0;bXMjYbmY" ascii
    $s9  = "function zPMuSwAMP(jfBNfPFMQ,osivOEb,zaHPhkux){" fullword ascii
    $s10 = ".floor(Math.random()*YPFRjeKT.length));}return lcXwm;}" fullword ascii
    $s11 = "function KpxU(gbfRbq,weGctmH){Cvvq = IPIxPNxGcUAODIqUsCHHK[11].split(IPIxPNxGcUAODIqUsCHHK[12]);weGctmH.open(Cvvq[0]+Cvvq[2]+Cvv" ascii
    $s12 = "function OGnDE(jIuVTj){return new ActiveXObject(jIuVTj);}" fullword ascii
    $s13 = "function qWwXDpx() {var FOcY=100000;var mWOMky = 100;return Math.random()*(FOcY-mWOMky)+mWOMky;}" fullword ascii
    $s14 = "aTgrI<EdvCIM.length;OCaaTgrI++) {mGLAMPD+=uFVVu[EdvCIM[OCaaTgrI]];}return mGLAMPD.substring(3,mGLAMPD.length);}" fullword ascii
    $s15 = "function PWAEG(kCllRXJi,EdvCIM,uXPqeAjGy){uFVVu=kCllRXJi.split(uXPqeAjGy);mGLAMPD = IPIxPNxGcUAODIqUsCHHK[13];for(OCaaTgrI=0;OCa" ascii
    $s16 = "function PWAEG(kCllRXJi,EdvCIM,uXPqeAjGy){uFVVu=kCllRXJi.split(uXPqeAjGy);mGLAMPD = IPIxPNxGcUAODIqUsCHHK[13];for(OCaaTgrI=0;OCa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}