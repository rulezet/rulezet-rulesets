rule sig_20160520_3b0c2c52873dc9d3a56ae5620ecedab4 {
  meta:
    description = "datamaliciousorder - file 20160520_3b0c2c52873dc9d3a56ae5620ecedab4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00793b644601092399738ff3c473f7ef78793d7767f09d57fcb5003f2fb9adfa"

  strings:
    $s1  = "function fMEsSyVV(KkUfF) {var BllcCgiY=sVDUhsQNgMBpxWairURA[2];for(var SrnTC=0;SrnTC<KkUfF;SrnTC++){cqLlZ+=BllcCgiY.charAt(Math." ascii
    $s2  = "function fMEsSyVV(KkUfF) {var BllcCgiY=sVDUhsQNgMBpxWairURA[2];for(var SrnTC=0;SrnTC<KkUfF;SrnTC++){cqLlZ+=BllcCgiY.charAt(Math." ascii
    $s3  = "function qDsYwbAVU(QGWQwhcAQ,rUknJCe,HiFTpljQ){" fullword ascii
    $s4  = "XeyI<IXKowa.length;yMWRXeyI++) {HITxpbj+=PlrFs[IXKowa[yMWRXeyI]];}return HITxpbj.substring(3,HITxpbj.length);}" fullword ascii
    $s5  = "function xNiGZ(CSRASnGQ,IXKowa,pLhcfAniu){PlrFs=CSRASnGQ.split(pLhcfAniu);HITxpbj = sVDUhsQNgMBpxWairURA[13];for(yMWRXeyI=0;yMWR" ascii
    $s6  = "function xNiGZ(CSRASnGQ,IXKowa,pLhcfAniu){PlrFs=CSRASnGQ.split(pLhcfAniu);HITxpbj = sVDUhsQNgMBpxWairURA[13];for(yMWRXeyI=0;yMWR" ascii
    $s7  = "function jczPR(NJPlMp){return new ActiveXObject(NJPlMp);}" fullword ascii
    $s8  = "3], wfHWkC, false);FqqlyDM.send();}" fullword ascii
    $s9  = "try{paZeRXt=qDsYwbAVU(MIQvr[UiHU], NgBNUki() + sVDUhsQNgMBpxWairURA[9], 1)}catch(e){}; " fullword ascii
    $s10 = "floor(Math.random()*BllcCgiY.length));}return cqLlZ;}" fullword ascii
    $s11 = "if (paZeRXt==0) break;" fullword ascii
    $s12 = "function rHELm(vqDMIkBQ,bWWUE,MHZWsaChYT){vqDMIkBQ.open();vqDMIkBQ.type = 1;vqDMIkBQ.write(bWWUE);vqDMIkBQ.position = 0;vqDMIkBQ" ascii
    $s13 = "function CRrD(wfHWkC,FqqlyDM){NXbW = sVDUhsQNgMBpxWairURA[11].split(sVDUhsQNgMBpxWairURA[12]);FqqlyDM.open(NXbW[0]+NXbW[2]+NXbW[" ascii
    $s14 = "function rHELm(vqDMIkBQ,bWWUE,MHZWsaChYT){vqDMIkBQ.open();vqDMIkBQ.type = 1;vqDMIkBQ.write(bWWUE);vqDMIkBQ.position = 0;vqDMIkBQ" ascii
    $s15 = "function CRrD(wfHWkC,FqqlyDM){NXbW = sVDUhsQNgMBpxWairURA[11].split(sVDUhsQNgMBpxWairURA[12]);FqqlyDM.open(NXbW[0]+NXbW[2]+NXbW[" ascii
    $s16 = "function NgBNUki() {var Lwzw=100000;var xlYWID = 100;return Math.random()*(Lwzw-xlYWID)+xlYWID;}" fullword ascii
    $s17 = "function ghYYzX(NJPlMp){return NJPlMp.ExpandEnvironmentStrings(sVDUhsQNgMBpxWairURA[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}