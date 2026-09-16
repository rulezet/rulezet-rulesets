rule sig_20160523_801b11ed99abe8bc796a3970764e983c {
  meta:
    description = "datamaliciousorder - file 20160523_801b11ed99abe8bc796a3970764e983c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ddd06b39c4dce0c063a26a61deb9c5d3994bac14c49a0bcba2607ec2c947502"

  strings:
    $s1  = "function KZEuncBL(YdRCJ) {var bgGKuzhV=nYRtROEQhLud[2];for(var hASHL=0;hASHL<YdRCJ;hASHL++){pWMfv+=bgGKuzhV.charAt(Math.floor(Ma" ascii
    $s2  = "function KZEuncBL(YdRCJ) {var bgGKuzhV=nYRtROEQhLud[2];for(var hASHL=0;hASHL<YdRCJ;hASHL++){pWMfv+=bgGKuzhV.charAt(Math.floor(Ma" ascii
    $s3  = "LjO.length;gDtJDjUP++) {awpRuVs+=nDeHX[dqfLjO[gDtJDjUP]];}return awpRuVs.substring(3,awpRuVs.length);}" fullword ascii
    $s4  = "function TULLmKIBUn(pcAUeury,ZidqzvXoDOJJ) {pcAUeury.Run(ZidqzvXoDOJJ, 0x1, 0x0);}" fullword ascii
    $s5  = "function jrqQDk(STlugO){return STlugO.ExpandEnvironmentStrings(nYRtROEQhLud[10])}" fullword ascii
    $s6  = "function eaGpP(dyYMzKKh,dqfLjO,nIHcNMREK){nDeHX=dyYMzKKh.split(nIHcNMREK);awpRuVs = nYRtROEQhLud[13];for(gDtJDjUP=0;gDtJDjUP<dqf" ascii
    $s7  = "function mynE(UgVNbI) {UgVNbI.open();}" fullword ascii
    $s8  = "try{iHPRmge=HVKFkirrb(LYDpR[tmbH], pCCorYw() + nYRtROEQhLud[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function vDie(AToAHX,VyjmjkY){LJvq = nYRtROEQhLud[11].split(nYRtROEQhLud[12]);VyjmjkY.open(LJvq[0]+LJvq[2]+LJvq[3], AToAHX, fals" ascii
    $s10 = "function tbRUHOG(nYpX,iKbVQ) {nYpX.write(iKbVQ);}" fullword ascii
    $s11 = "function pCCorYw() {var GPhu=100000;var ZUXwWs = 100;return WDQEFtc()*(GPhu-ZUXwWs)+ZUXwWs;}" fullword ascii
    $s12 = "function FwDJbWbn(ufsZwpcZs) {ufsZwpcZs.type=1;}" fullword ascii
    $s13 = "function IWeYkAERj(KafWZw) {var apqxoGkigM=[];KafWZw.position=apqxoGkigM.length*(3135504-684);}" fullword ascii
    $s14 = "function WDQEFtc(){return Math.random();}" fullword ascii
    $s15 = "if (iHPRmge==0) break;" fullword ascii
    $s16 = "th.random()*bgGKuzhV.length));}return pWMfv;}" fullword ascii
    $s17 = "function eaGpP(dyYMzKKh,dqfLjO,nIHcNMREK){nDeHX=dyYMzKKh.split(nIHcNMREK);awpRuVs = nYRtROEQhLud[13];for(gDtJDjUP=0;gDtJDjUP<dqf" ascii
    $s18 = "function TJfdH(STlugO){return new ActiveXObject(STlugO);}" fullword ascii
    $s19 = "function HWPmCEA(wCYzc) {wCYzc.close();}" fullword ascii
    $s20 = "function vDie(AToAHX,VyjmjkY){LJvq = nYRtROEQhLud[11].split(nYRtROEQhLud[12]);VyjmjkY.open(LJvq[0]+LJvq[2]+LJvq[3], AToAHX, fals" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}