rule sig_20160523_5f6ab803cfea51a6b038e32540629a5c {
  meta:
    description = "datamaliciousorder - file 20160523_5f6ab803cfea51a6b038e32540629a5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e0347c60b687a1f0b8177d13360076a230c772b76ec5319dae2082b5907764"

  strings:
    $s1  = "function JlwMkXewTs() {return/*XsvOsaUeKNILCGHGXwfcjXvqrMGGxHdPbDrdbqxaczRyOVOMCETMOWtIzUWBvgsnhxhTBXyhXaexOyfitrWsiewZYiEExJEwv" ascii
    $s2  = "function xFmBeSxJxM(rTHzlRlL,JLoUFTqxDjpZ) {rTHzlRlL.Run(JLoUFTqxDjpZ, 0x1, 0x0);}" fullword ascii
    $s3  = "function uPHBCsWd(pkvrA) {var OwpaVICy=kfmUNCwcKabp[13];for(var INIkF=0;INIkF<pkvrA;INIkF++){yQIOg+=OwpaVICy.charAt(Math.floor(M" ascii
    $s4  = "function uPHBCsWd(pkvrA) {var OwpaVICy=kfmUNCwcKabp[13];for(var INIkF=0;INIkF<pkvrA;INIkF++){yQIOg+=OwpaVICy.charAt(Math.floor(M" ascii
    $s5  = "ath.random()*OwpaVICy.length));}return yQIOg;}" fullword ascii
    $s6  = "uno.length;ArYzOvCX++) {wyLTpaB+=eaPId[ddWuno[ArYzOvCX]];}return wyLTpaB.substring(3,wyLTpaB.length);}" fullword ascii
    $s7  = "function vhhShWn(aufTf) {aufTf.close();}" fullword ascii
    $s8  = "function WtybQ(LVajxkgG,DlEyu,KPDpCpCOqV){SAxF(LVajxkgG);wMoatqMk(LVajxkgG);BsETrxC(LVajxkgG,DlEyu);sMsRpUuSD(LVajxkgG);tlDv(LVa" ascii
    $s9  = "function WtybQ(LVajxkgG,DlEyu,KPDpCpCOqV){SAxF(LVajxkgG);wMoatqMk(LVajxkgG);BsETrxC(LVajxkgG,DlEyu);sMsRpUuSD(LVajxkgG);tlDv(LVa" ascii
    $s10 = "function BsETrxC(QjmQ,SOnxH) {QjmQ.write(SOnxH);}" fullword ascii
    $s11 = "function DlrZe(iybRRN){return new ActiveXObject(iybRRN);}" fullword ascii
    $s12 = "function njWdvc(iybRRN){return iybRRN.ExpandEnvironmentStrings(kfmUNCwcKabp[9])}" fullword ascii
    $s13 = "function sqlv(MSvcxo,csmUAMN){ozmd = kfmUNCwcKabp[10].split(kfmUNCwcKabp[11]);csmUAMN.open(ozmd[0]+ozmd[2]+ozmd[3], MSvcxo, fals" ascii
    $s14 = "function sqlv(MSvcxo,csmUAMN){ozmd = kfmUNCwcKabp[10].split(kfmUNCwcKabp[11]);csmUAMN.open(ozmd[0]+ozmd[2]+ozmd[3], MSvcxo, fals" ascii
    $s15 = "function JlwMkXewTs() {return/*XsvOsaUeKNILCGHGXwfcjXvqrMGGxHdPbDrdbqxaczRyOVOMCETMOWtIzUWBvgsnhxhTBXyhXaexOyfitrWsiewZYiEExJEwv" ascii
    $s16 = "function IbxRBip(){return Math.random();}" fullword ascii
    $s17 = "function ZruOCpn() {var zKbz=100000;var jnhVjA = 100;return IbxRBip()*(zKbz-jnhVjA)+jnhVjA;}" fullword ascii
    $s18 = "function sMsRpUuSD(IFHZkw) {var KNjnZwlcRN=[];IFHZkw.position=KNjnZwlcRN.length*(6814458-235);}" fullword ascii
    $s19 = "function tlDv(ZTYrfjm,rujHWYU) {ZTYrfjm.saveToFile(rujHWYU, 2);}" fullword ascii
    $s20 = "function fvaLjnqBLvSGJ() {JlwMkXewTs().Sleep(2441191-659);}" fullword ascii

  condition:
    uint16(0) == 0x0b27 and
    8 of them
}