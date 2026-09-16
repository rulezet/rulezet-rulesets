rule sig_20160520_21c0c7b0378a3219da83411049feb667 {
  meta:
    description = "datamaliciousorder - file 20160520_21c0c7b0378a3219da83411049feb667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb244b1f2c295f9babe1e87f0ad8b38c0093118b1e97456d9e719ca2770dfbd"

  strings:
    $s1  = "function PpTVLFea(GpPdy) {var YMzKKhdq=VdexDUwTkiyVen[2];for(var fLjOn=0;fLjOn<GpPdy;fLjOn++){IHcNM+=YMzKKhdq.charAt(Math.floor(" ascii
    $s2  = "function PpTVLFea(GpPdy) {var YMzKKhdq=VdexDUwTkiyVen[2];for(var fLjOn=0;fLjOn<GpPdy;fLjOn++){IHcNM+=YMzKKhdq.charAt(Math.floor(" ascii
    $s3  = "JEKRl.length;kcOWlwnA++) {MAQCeXA+=XAydP[zJEKRl[kcOWlwnA]];}return MAQCeXA.substring(3,MAQCeXA.length);}" fullword ascii
    $s4  = "Math.random()*YMzKKhdq.length));}return IHcNM;}" fullword ascii
    $s5  = "function bjNcy(UPSnaVhl,zJEKRl,vCYesfuvG){XAydP=UPSnaVhl.split(vCYesfuvG);MAQCeXA = VdexDUwTkiyVen[13];for(kcOWlwnA=0;kcOWlwnA<z" ascii
    $s6  = "function bjNcy(UPSnaVhl,zJEKRl,vCYesfuvG){XAydP=UPSnaVhl.split(vCYesfuvG);MAQCeXA = VdexDUwTkiyVen[13];for(kcOWlwnA=0;kcOWlwnA<z" ascii
    $s7  = "function HrzuM(JfNpULGp,EeqjS,uJXpsddYlq){JfNpULGp.open();JfNpULGp.type = 1;JfNpULGp.write(EeqjS);JfNpULGp.position = 0;JfNpULGp" ascii
    $s8  = "if (eHXawpR==0) break;" fullword ascii
    $s9  = "function qSzrfFl() {var IIxX=100000;var HSsoYY = 100;return Math.random()*(IIxX-HSsoYY)+HSsoYY;}" fullword ascii
    $s10 = "function HrzuM(JfNpULGp,EeqjS,uJXpsddYlq){JfNpULGp.open();JfNpULGp.type = 1;JfNpULGp.write(EeqjS);JfNpULGp.position = 0;JfNpULGp" ascii
    $s11 = "function DtJDjUPnD(uVsGcYWDQ,EFtcmyn,EUgVNbIF){" fullword ascii
    $s12 = "false);RkPHxsi.send();}" fullword ascii
    $s13 = "function zAKO(JZZpHZ,RkPHxsi){ABei = VdexDUwTkiyVen[11].split(VdexDUwTkiyVen[12]);RkPHxsi.open(ABei[0]+ABei[2]+ABei[3], JZZpHZ, " ascii
    $s14 = "function zAKO(JZZpHZ,RkPHxsi){ABei = VdexDUwTkiyVen[11].split(VdexDUwTkiyVen[12]);RkPHxsi.open(ABei[0]+ABei[2]+ABei[3], JZZpHZ, " ascii
    $s15 = "try{eHXawpR=DtJDjUPnD(kYLJv[ULLm], qSzrfFl() + VdexDUwTkiyVen[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function ryZidq(pcAUeu){return pcAUeu.ExpandEnvironmentStrings(VdexDUwTkiyVen[10])}" fullword ascii
    $s17 = "function KIBUn(pcAUeu){return new ActiveXObject(pcAUeu);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}