rule sig_20160531_4b94ef7574625d0ae79037904d573c7a {
  meta:
    description = "datamaliciousorder - file 20160531_4b94ef7574625d0ae79037904d573c7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e550ae3772a59a73ab06c86b19d5eae148b37017c031012733baa596957f402c"

  strings:
    $s1  = "var OQIulPbMEvlr=function(){return WScript.CreateObject(byINosbYJvnntAwL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function NxOirZzWJiVllUae(bUlIq,SawxqVIdPFZXXnMpvGtgOAb){return bUlIq.charAt(SawxqVIdPFZXXnMpvGtgOAb);}" fullword ascii
    $s3  = "function OgrURtNcMfjDA(){return DlBNQzmHMbqooQ(byINosbYJvnntAwL[9],[1,5,7],byINosbYJvnntAwL[10]);}" fullword ascii
    $s4  = "function DYkmtZZtpgoylVDDPJ(klpUSkAq,IYhZmNlml,TyqdpMSwrKcfblqTWzKRok){return String.fromCharCode(klpUSkAq,IYhZmNlml,TyqdpMSwrKc" ascii
    $s5  = "var YOnvdL=function(){return new ActiveXObject(byINosbYJvnntAwL[1]);}();" fullword ascii
    $s6  = "function DYkmtZZtpgoylVDDPJ(klpUSkAq,IYhZmNlml,TyqdpMSwrKcfblqTWzKRok){return String.fromCharCode(klpUSkAq,IYhZmNlml,TyqdpMSwrKc" ascii
    $s7  = "(JJaPhETuwxTsI,0x1,0x0)}function XybUljUU(IRUvsazQuLvizf,QJhhaWiTOPZ,zDQkYyAuP){var yqZkuRazvxgUq=IRUvsazQuLvizf.createtextfile(" ascii
    $s8  = "function dNPnjAZnnrXvTEsXWSAlcnGX(hPYGzjDPjwZEpiLk,PqFTgveEsEtUFYvAoNQaZ){return String.fromCharCode(hPYGzjDPjwZEpiLk,PqFTgveEsE" ascii
    $s9  = " & 0xff;if (UiZBRBqdViXeNkWSEMMmBi == 64) ElvxvAevtqqSLQoBD += Iy(unVCgBhylDvqGs);else if (oFcpckDRHCqiAcnAzNQi == 64) ElvxvAevt" ascii
    $s10 = "function xVaeGjVYpu(){return DlBNQzmHMbqooQ(byINosbYJvnntAwL[13],[0,3,6],byINosbYJvnntAwL[14]);}" fullword ascii
    $s11 = "function dNPnjAZnnrXvTEsXWSAlcnGX(hPYGzjDPjwZEpiLk,PqFTgveEsEtUFYvAoNQaZ){return String.fromCharCode(hPYGzjDPjwZEpiLk,PqFTgveEsE" ascii
    $s12 = "QJhhaWiTOPZ,true);yqZkuRazvxgUq.WriteLine(zDQkYyAuP);yqZkuRazvxgUq.Close();}" fullword ascii
    $s13 = "DC, KNFZcbOkWEYQHJGWbNE);} while (uERVyl < FDgvKidNCHKya.length);return ElvxvAevtqqSLQoBD;}" fullword ascii
    $s14 = "or(sjwRlMwmgspuD=0;sjwRlMwmgspuD<rpwQaX.length;sjwRlMwmgspuD++) {zDpkufYOi+=DkuvPKqtY[rpwQaX[sjwRlMwmgspuD]];}return zDpkufYOi.s" ascii
    $s15 = "function Iy(GsAPDcSPwHt){return String.fromCharCode(GsAPDcSPwHt);}" fullword ascii
    $s16 = "function rpoYXWdo(FDgvKidNCHKya) {var gTfvaQkNaiYptedBiO = UlfhaqBb.join(byINosbYJvnntAwL[7]);var unVCgBhylDvqGs, RbXOHDC, KNFZc" ascii
    $s17 = "function DlBNQzmHMbqooQ(xELDixdqdKwf,rpwQaX,xlATTgAsJ){DkuvPKqtY=xELDixdqdKwf.split(xlATTgAsJ);zDpkufYOi = byINosbYJvnntAwL[0];f" ascii
    $s18 = "function DlBNQzmHMbqooQ(xELDixdqdKwf,rpwQaX,xlATTgAsJ){DkuvPKqtY=xELDixdqdKwf.split(xlATTgAsJ);zDpkufYOi = byINosbYJvnntAwL[0];f" ascii
    $s19 = "function vAkzBhWIMh(){return OQIulPbMEvlr.ExpandEnvironmentStrings(OgrURtNcMfjDA())}" fullword ascii
    $s20 = "(JJaPhETuwxTsI,0x1,0x0)}function XybUljUU(IRUvsazQuLvizf,QJhhaWiTOPZ,zDQkYyAuP){var yqZkuRazvxgUq=IRUvsazQuLvizf.createtextfile(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}