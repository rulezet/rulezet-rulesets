rule sig_20160520_a3c5b292fc9de63fad12426e0c25969b {
  meta:
    description = "datamaliciousorder - file 20160520_a3c5b292fc9de63fad12426e0c25969b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffe9913e9b1ae507a5d456a4f6fc44b534a456b6610d4b5a391df19151430aa5"

  strings:
    $s1  = "function vVDGkNQI(Sryep) {var olkbIpTa=IDoCwocmmsCRmFZSCblsm[2];for(var evwLH=0;evwLH<Sryep;evwLH++){QMeVj+=olkbIpTa.charAt(Math" ascii
    $s2  = "function vVDGkNQI(Sryep) {var olkbIpTa=IDoCwocmmsCRmFZSCblsm[2];for(var evwLH=0;evwLH<Sryep;evwLH++){QMeVj+=olkbIpTa.charAt(Math" ascii
    $s3  = "function iPNl(svmqjX,hjezJJc){HDgC = IDoCwocmmsCRmFZSCblsm[11].split(IDoCwocmmsCRmFZSCblsm[12]);hjezJJc.open(HDgC[0]+HDgC[2]+HDg" ascii
    $s4  = "function qdamk(qPICFP){return new ActiveXObject(qPICFP);}" fullword ascii
    $s5  = ".floor(Math.random()*olkbIpTa.length));}return QMeVj;}" fullword ascii
    $s6  = "function xpAmcCBTN(ubboAraHf,exNCMyQ,InHBPfeh){" fullword ascii
    $s7  = "function SMNCLTA() {var wMXH=100000;var RNYMyf = 100;return Math.random()*(wMXH-RNYMyf)+RNYMyf;}" fullword ascii
    $s8  = "try{sHsVkWV=xpAmcCBTN(WOgpX[BtpJ], SMNCLTA() + IDoCwocmmsCRmFZSCblsm[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function TdPmR(WyDhdbNM,bjhhX,iFouKxGzZC){WyDhdbNM.open();WyDhdbNM.type = 1;WyDhdbNM.write(bjhhX);WyDhdbNM.position = 0;WyDhdbNM" ascii
    $s10 = "function kUpkY(mGRyRtOA,KiOxnf,chBMpVWlM){HoYYk=mGRyRtOA.split(chBMpVWlM);aHvbLgH = IDoCwocmmsCRmFZSCblsm[13];for(FyffDFzF=0;Fyf" ascii
    $s11 = "fDFzF<KiOxnf.length;FyffDFzF++) {aHvbLgH+=HoYYk[KiOxnf[FyffDFzF]];}return aHvbLgH.substring(3,aHvbLgH.length);}" fullword ascii
    $s12 = "function TdPmR(WyDhdbNM,bjhhX,iFouKxGzZC){WyDhdbNM.open();WyDhdbNM.type = 1;WyDhdbNM.write(bjhhX);WyDhdbNM.position = 0;WyDhdbNM" ascii
    $s13 = "function ilTEyA(qPICFP){return qPICFP.ExpandEnvironmentStrings(IDoCwocmmsCRmFZSCblsm[10])}" fullword ascii
    $s14 = "function kUpkY(mGRyRtOA,KiOxnf,chBMpVWlM){HoYYk=mGRyRtOA.split(chBMpVWlM);aHvbLgH = IDoCwocmmsCRmFZSCblsm[13];for(FyffDFzF=0;Fyf" ascii
    $s15 = "if (sHsVkWV==0) break;" fullword ascii
    $s16 = "function iPNl(svmqjX,hjezJJc){HDgC = IDoCwocmmsCRmFZSCblsm[11].split(IDoCwocmmsCRmFZSCblsm[12]);hjezJJc.open(HDgC[0]+HDgC[2]+HDg" ascii
    $s17 = "C[3], svmqjX, false);hjezJJc.send();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}