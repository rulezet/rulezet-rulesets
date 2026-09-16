rule sig_20160520_c5f7132bafca4d229a95d0545acd3888 {
  meta:
    description = "datamaliciousorder - file 20160520_c5f7132bafca4d229a95d0545acd3888.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a98427cb9f363d227ac1c7b2dc4657e98e6dddf784f21148f9118eb458c0836e"

  strings:
    $s1  = "function dYWtlhF() {var ZnqN=100000;var cOmNaS = 100;return Math.random()*(ZnqN-cOmNaS)+cOmNaS;}" fullword ascii
    $s2  = "function fxReHhaE(dLzWf) {var zNlYqNct=aTtivQH[2];for(var CZACa=0;CZACa<dLzWf;CZACa++){vjkcy+=zNlYqNct.charAt(Math.floor(Math.ra" ascii
    $s3  = "function fxReHhaE(dLzWf) {var zNlYqNct=aTtivQH[2];for(var CZACa=0;CZACa<dLzWf;CZACa++){vjkcy+=zNlYqNct.charAt(Math.floor(Math.ra" ascii
    $s4  = "ength;JjpaYyBL++) {rMLrSTw+=TgMYx[MDCYOu[JjpaYyBL]];}return rMLrSTw.substring(3,rMLrSTw.length);}" fullword ascii
    $s5  = "function oGKf(CUCcLv,ZzbdZcl){ibOy = aTtivQH[11].split(aTtivQH[12]);ZzbdZcl.open(ibOy[0]+ibOy[2]+ibOy[3], CUCcLv, false);ZzbdZcl" ascii
    $s6  = "function TPITis(QfDFeV){return QfDFeV.ExpandEnvironmentStrings(aTtivQH[10])}" fullword ascii
    $s7  = "ndom()*zNlYqNct.length));}return vjkcy;}" fullword ascii
    $s8  = "function AfeNK(QfDFeV){return new ActiveXObject(QfDFeV);}" fullword ascii
    $s9  = "function SDYOP(CPPgUwjD,XsarC,BShdvSlpZD){CPPgUwjD.open();CPPgUwjD.type = 1;CPPgUwjD.write(XsarC);CPPgUwjD.position = 0;CPPgUwjD" ascii
    $s10 = "if (zxiMRec==0) break;" fullword ascii
    $s11 = "function SDYOP(CPPgUwjD,XsarC,BShdvSlpZD){CPPgUwjD.open();CPPgUwjD.type = 1;CPPgUwjD.write(XsarC);CPPgUwjD.position = 0;CPPgUwjD" ascii
    $s12 = "function oGKf(CUCcLv,ZzbdZcl){ibOy = aTtivQH[11].split(aTtivQH[12]);ZzbdZcl.open(ibOy[0]+ibOy[2]+ibOy[3], CUCcLv, false);ZzbdZcl" ascii
    $s13 = "function CQFvn(LNDWyYxh,MDCYOu,RbqQOuCJs){TgMYx=LNDWyYxh.split(RbqQOuCJs);rMLrSTw = aTtivQH[13];for(JjpaYyBL=0;JjpaYyBL<MDCYOu.l" ascii
    $s14 = "function CQFvn(LNDWyYxh,MDCYOu,RbqQOuCJs){TgMYx=LNDWyYxh.split(RbqQOuCJs);rMLrSTw = aTtivQH[13];for(JjpaYyBL=0;JjpaYyBL<MDCYOu.l" ascii
    $s15 = "function fqOXbMHPB(mzSTgHGHY,bLRUSZt,zTOORnWY){" fullword ascii
    $s16 = "try{zxiMRec=fqOXbMHPB(dKEUl[UNby], dYWtlhF() + aTtivQH[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}