rule sig_20160520_c038fee6006d06e884d41cdd6ad9733d {
  meta:
    description = "datamaliciousorder - file 20160520_c038fee6006d06e884d41cdd6ad9733d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a79bc80568e329933c5ae94dd143b960efafdcf39cae161ad3a9948a33f280c5"

  strings:
    $s1  = "function tpyLGZSv(uexMX) {var wmpYsJjK=OJzzWDjtDKsItTBHoTl[2];for(var KNYRR=0;KNYRR<uexMX;KNYRR++){VNGDg+=wmpYsJjK.charAt(Math.f" ascii
    $s2  = "function tpyLGZSv(uexMX) {var wmpYsJjK=OJzzWDjtDKsItTBHoTl[2];for(var KNYRR=0;KNYRR<uexMX;KNYRR++){VNGDg+=wmpYsJjK.charAt(Math.f" ascii
    $s3  = "if (bczfPac==0) break;" fullword ascii
    $s4  = "function ANgak(jRJhegZu,JSWCKs,YLtydzuCJ){RoxVW=jRJhegZu.split(YLtydzuCJ);VPrfZqh = OJzzWDjtDKsItTBHoTl[13];for(XZvPKTwU=0;XZvPK" ascii
    $s5  = "function WZrI(zYMofn,hJBjaYY){EqLg = OJzzWDjtDKsItTBHoTl[11].split(OJzzWDjtDKsItTBHoTl[12]);hJBjaYY.open(EqLg[0]+EqLg[2]+EqLg[3]" ascii
    $s6  = "function jAaMCH(imkaSu){return imkaSu.ExpandEnvironmentStrings(OJzzWDjtDKsItTBHoTl[10])}" fullword ascii
    $s7  = "function mzNgFAvrt(UaiYsuRMD,iTqgbFi,hmVojzfe){" fullword ascii
    $s8  = "function ANgak(jRJhegZu,JSWCKs,YLtydzuCJ){RoxVW=jRJhegZu.split(YLtydzuCJ);VPrfZqh = OJzzWDjtDKsItTBHoTl[13];for(XZvPKTwU=0;XZvPK" ascii
    $s9  = "function SMdzZ(mFljFTeG,MQJcW,VeJdhVmyXm){mFljFTeG.open();mFljFTeG.type = 1;mFljFTeG.write(MQJcW);mFljFTeG.position = 0;mFljFTeG" ascii
    $s10 = "TwU<JSWCKs.length;XZvPKTwU++) {VPrfZqh+=RoxVW[JSWCKs[XZvPKTwU]];}return VPrfZqh.substring(3,VPrfZqh.length);}" fullword ascii
    $s11 = "function iJvFF(imkaSu){return new ActiveXObject(imkaSu);}" fullword ascii
    $s12 = "loor(Math.random()*wmpYsJjK.length));}return VNGDg;}" fullword ascii
    $s13 = ", zYMofn, false);hJBjaYY.send();}" fullword ascii
    $s14 = "function UadlRnG() {var vXik=100000;var YrYHRC = 100;return Math.random()*(vXik-YrYHRC)+YrYHRC;}" fullword ascii
    $s15 = "function SMdzZ(mFljFTeG,MQJcW,VeJdhVmyXm){mFljFTeG.open();mFljFTeG.type = 1;mFljFTeG.write(MQJcW);mFljFTeG.position = 0;mFljFTeG" ascii
    $s16 = "try{bczfPac=mzNgFAvrt(xALkT[fMEY], UadlRnG() + OJzzWDjtDKsItTBHoTl[9], 1)}catch(e){}; " fullword ascii
    $s17 = "function WZrI(zYMofn,hJBjaYY){EqLg = OJzzWDjtDKsItTBHoTl[11].split(OJzzWDjtDKsItTBHoTl[12]);hJBjaYY.open(EqLg[0]+EqLg[2]+EqLg[3]" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}