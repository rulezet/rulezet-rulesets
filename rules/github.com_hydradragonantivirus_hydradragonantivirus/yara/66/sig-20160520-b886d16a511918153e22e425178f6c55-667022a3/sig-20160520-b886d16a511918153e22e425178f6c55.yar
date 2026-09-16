rule sig_20160520_b886d16a511918153e22e425178f6c55 {
  meta:
    description = "datamaliciousorder - file 20160520_b886d16a511918153e22e425178f6c55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94324515aea081cb919d63f3a440f5f955eb4bd4fde4b62d97d62c5e609937ff"

  strings:
    $s1  = "function yeZLIFwj(YnwLh) {var sxyuNzZx=QherBcguo[2];for(var QYvAs=0;QYvAs<YnwLh;QYvAs++){VppLM+=sxyuNzZx.charAt(Math.floor(Math." ascii
    $s2  = "function yeZLIFwj(YnwLh) {var sxyuNzZx=QherBcguo[2];for(var QYvAs=0;QYvAs<YnwLh;QYvAs++){VppLM+=sxyuNzZx.charAt(Math.floor(Math." ascii
    $s3  = "function bscIu(GBlGMq){return new ActiveXObject(GBlGMq);}" fullword ascii
    $s4  = "function yliqB(gzhLhsdN,GnjUvi,eQRBTMNrg){qtCkz=gzhLhsdN.split(eQRBTMNrg);KOpolPr = QherBcguo[13];for(vAcXbWGX=0;vAcXbWGX<GnjUvi" ascii
    $s5  = "function yliqB(gzhLhsdN,GnjUvi,eQRBTMNrg){qtCkz=gzhLhsdN.split(eQRBTMNrg);KOpolPr = QherBcguo[13];for(vAcXbWGX=0;vAcXbWGX<GnjUvi" ascii
    $s6  = "function KoMYCem() {var SCiz=100000;var vnlQhO = 100;return Math.random()*(SCiz-vnlQhO)+vnlQhO;}" fullword ascii
    $s7  = "function pzgQU(TkYWTiDM,YhOjg,LsDQaBMZDY){TkYWTiDM.open();TkYWTiDM.type = 1;TkYWTiDM.write(YhOjg);TkYWTiDM.position = 0;TkYWTiDM" ascii
    $s8  = "try{sxSzmNPSX(TTAgP[sgUs], KoMYCem() + QherBcguo[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function ehAW(umvhdL,vOUEcFn){pxQY = QherBcguo[11].split(QherBcguo[12]);vOUEcFn.open(pxQY[0]+pxQY[2]+pxQY[3], umvhdL, false);vOU" ascii
    $s10 = "function ehAW(umvhdL,vOUEcFn){pxQY = QherBcguo[11].split(QherBcguo[12]);vOUEcFn.open(pxQY[0]+pxQY[2]+pxQY[3], umvhdL, false);vOU" ascii
    $s11 = "function GyeUYh(GBlGMq){return GBlGMq.ExpandEnvironmentStrings(QherBcguo[10])}" fullword ascii
    $s12 = ".length;vAcXbWGX++) {KOpolPr+=qtCkz[GnjUvi[vAcXbWGX]];}return KOpolPr.substring(3,KOpolPr.length);}" fullword ascii
    $s13 = "random()*sxyuNzZx.length));}return VppLM;}" fullword ascii
    $s14 = "function pzgQU(TkYWTiDM,YhOjg,LsDQaBMZDY){TkYWTiDM.open();TkYWTiDM.type = 1;TkYWTiDM.write(YhOjg);TkYWTiDM.position = 0;TkYWTiDM" ascii
    $s15 = "function sxSzmNPSX(IXZGuhTQJ,NZILEoL,maleySOt){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}