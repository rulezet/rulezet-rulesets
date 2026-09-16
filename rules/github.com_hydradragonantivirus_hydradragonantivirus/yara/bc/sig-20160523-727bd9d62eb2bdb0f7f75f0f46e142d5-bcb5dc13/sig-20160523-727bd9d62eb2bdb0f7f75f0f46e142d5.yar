rule sig_20160523_727bd9d62eb2bdb0f7f75f0f46e142d5 {
  meta:
    description = "datamaliciousorder - file 20160523_727bd9d62eb2bdb0f7f75f0f46e142d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68dabf478688823222929033df2ee071832df473b509d8635c4c4995a7cbed39"

  strings:
    $s1  = "function ubgbaylYLd(gfsPwhnf,nroZjuNUpABP) {gfsPwhnf.Run(nroZjuNUpABP, 0x1, 0x0);}" fullword ascii
    $s2  = "function fdciWWkW(LPEbU) {var LvpwpweR=zqpDUxkVHAEoR[13];for(var HQnbr=0;HQnbr<LPEbU;HQnbr++){qgAyi+=LvpwpweR.charAt(Math.floor(" ascii
    $s3  = "function fdciWWkW(LPEbU) {var LvpwpweR=zqpDUxkVHAEoR[13];for(var HQnbr=0;HQnbr<LPEbU;HQnbr++){qgAyi+=LvpwpweR.charAt(Math.floor(" ascii
    $s4  = "Math.random()*LvpwpweR.length));}return qgAyi;}" fullword ascii
    $s5  = "DhYI.length;TnuvqnPv++) {KHLZEOY+=RvaFo[UFDhYI[TnuvqnPv]];}return KHLZEOY.substring(3,KHLZEOY.length);}" fullword ascii
    $s6  = "function rhGKP(kWvxGUpF,UFDhYI,XuqjHjWLu){RvaFo=kWvxGUpF.split(XuqjHjWLu);KHLZEOY = zqpDUxkVHAEoR[12];for(TnuvqnPv=0;TnuvqnPv<UF" ascii
    $s7  = "function GctRX(NVfkGS){return new ActiveXObject(NVfkGS);}" fullword ascii
    $s8  = "function efzxoKX(){return Math.random();}" fullword ascii
    $s9  = "function InXT(NnJmrZ) {NnJmrZ.open();}" fullword ascii
    $s10 = "function GMbo(AXpTFO,sLURThR){lfZv = zqpDUxkVHAEoR[10].split(zqpDUxkVHAEoR[11]);sLURThR.open(lfZv[0]+lfZv[2]+lfZv[3], AXpTFO, fa" ascii
    $s11 = "function fgdWF(BgyBvVSt,TIVdz,eZgstWzepd){InXT(BgyBvVSt);mByIzIOa(BgyBvVSt);BfOFSZZ(BgyBvVSt,TIVdz);zqFdApjTE(BgyBvVSt);GDBS(Bgy" ascii
    $s12 = "function GDBS(CNjsBvb,kjltVEw) {CNjsBvb.saveToFile(kjltVEw, 2);}" fullword ascii
    $s13 = "function fgdWF(BgyBvVSt,TIVdz,eZgstWzepd){InXT(BgyBvVSt);mByIzIOa(BgyBvVSt);BfOFSZZ(BgyBvVSt,TIVdz);zqFdApjTE(BgyBvVSt);GDBS(Bgy" ascii
    $s14 = "function RmVTeaR() {var pXSs=100000;var dOlDvu = 100;return efzxoKX()*(pXSs-dOlDvu)+dOlDvu;}" fullword ascii
    $s15 = "function rhGKP(kWvxGUpF,UFDhYI,XuqjHjWLu){RvaFo=kWvxGUpF.split(XuqjHjWLu);KHLZEOY = zqpDUxkVHAEoR[12];for(TnuvqnPv=0;TnuvqnPv<UF" ascii
    $s16 = "function GMbo(AXpTFO,sLURThR){lfZv = zqpDUxkVHAEoR[10].split(zqpDUxkVHAEoR[11]);sLURThR.open(lfZv[0]+lfZv[2]+lfZv[3], AXpTFO, fa" ascii
    $s17 = "function oMcpFt(NVfkGS){return NVfkGS.ExpandEnvironmentStrings(zqpDUxkVHAEoR[9])}" fullword ascii
    $s18 = "function zqFdApjTE(ovpNSZ) {var JwghTGJFkO=[];ovpNSZ.position=JwghTGJFkO.length*(3150507-636);}" fullword ascii
    $s19 = "function fwrNBlB(uAnNe) {uAnNe.close();}" fullword ascii
    $s20 = "function BfOFSZZ(uuAY,vgnwb) {uuAY.write(vgnwb);}" fullword ascii

  condition:
    uint16(0) == 0x1d27 and
    8 of them
}