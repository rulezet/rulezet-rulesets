rule sig_20160520_cf20a99c66b513f2df05272d8e97a6cd {
  meta:
    description = "datamaliciousorder - file 20160520_cf20a99c66b513f2df05272d8e97a6cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b2268fd9ca55471e503553947941484511749d1955387c629d64ae7c4989511"

  strings:
    $s1  = "function ABufYJsE(lkwNO) {var hQzDgngd=DALPGhNR[2];for(var mXzod=0;mXzod<lkwNO;mXzod++){HXGLA+=hQzDgngd.charAt(Math.floor(Math.r" ascii
    $s2  = "function ABufYJsE(lkwNO) {var hQzDgngd=DALPGhNR[2];for(var mXzod=0;mXzod<lkwNO;mXzod++){HXGLA+=hQzDgngd.charAt(Math.floor(Math.r" ascii
    $s3  = "function PKzrvD(ROjrWf){return ROjrWf.ExpandEnvironmentStrings(DALPGhNR[10])}" fullword ascii
    $s4  = "andom()*hQzDgngd.length));}return HXGLA;}" fullword ascii
    $s5  = "function ziBcb(ESqhmkGh,GKkUKV,NLWWAzotj){nmGwi=ESqhmkGh.split(NLWWAzotj);NIYLNDB = DALPGhNR[13];for(AkraIKtJ=0;AkraIKtJ<GKkUKV." ascii
    $s6  = "function shak(YmlgKr,dJycojP){xdAF = DALPGhNR[11].split(DALPGhNR[12]);dJycojP.open(xdAF[0]+xdAF[2]+xdAF[3], YmlgKr, false);dJyco" ascii
    $s7  = "try{wVWAeDF=ZitnNOcdZ(IVZMD[nJSH], SVcNWQM() + DALPGhNR[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function shak(YmlgKr,dJycojP){xdAF = DALPGhNR[11].split(DALPGhNR[12]);dJycojP.open(xdAF[0]+xdAF[2]+xdAF[3], YmlgKr, false);dJyco" ascii
    $s9  = "length;AkraIKtJ++) {NIYLNDB+=nmGwi[GKkUKV[AkraIKtJ]];}return NIYLNDB.substring(3,NIYLNDB.length);}" fullword ascii
    $s10 = "function kMltG(ROjrWf){return new ActiveXObject(ROjrWf);}" fullword ascii
    $s11 = "function ZitnNOcdZ(KkfpsNfLS,lKecCwg,mlwcqkoE){" fullword ascii
    $s12 = "function ziBcb(ESqhmkGh,GKkUKV,NLWWAzotj){nmGwi=ESqhmkGh.split(NLWWAzotj);NIYLNDB = DALPGhNR[13];for(AkraIKtJ=0;AkraIKtJ<GKkUKV." ascii
    $s13 = "if (wVWAeDF==0) break;" fullword ascii
    $s14 = "function SVcNWQM() {var zaIv=100000;var wvUhRa = 100;return Math.random()*(zaIv-wvUhRa)+wvUhRa;}" fullword ascii
    $s15 = "function hLcan(vVnJXuLT,vJmQw,BhZegprXlb){vVnJXuLT.open();vVnJXuLT.type = 1;vVnJXuLT.write(vJmQw);vVnJXuLT.position = 0;vVnJXuLT" ascii
    $s16 = "function hLcan(vVnJXuLT,vJmQw,BhZegprXlb){vVnJXuLT.open();vVnJXuLT.type = 1;vVnJXuLT.write(vJmQw);vVnJXuLT.position = 0;vVnJXuLT" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}