rule sig_20160523_0fac8c0c74184ad6e53510d0bfae8878 {
  meta:
    description = "datamaliciousorder - file 20160523_0fac8c0c74184ad6e53510d0bfae8878.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e968a7f2c1c353feca640717d37dc46002eb3a71dc81c017716f6ed8a55a939e"

  strings:
    $s1  = "function QtJTefuQrb(MhlPgQXX,mCrCwZRGnlKy) {MhlPgQXX.Run(mCrCwZRGnlKy, 0x1, 0x0);}" fullword ascii
    $s2  = "function adHWMvvTkt() {return/*iXodyYEhKOyKxWmQfAZlRQCxtvmWUNLsYfJOtuQPFVHxEeCOPuXZlJEebYcfTbBpxGOWdTAYmMQQSLvdLhKfrXNsQmwpsWfYy" ascii
    $s3  = "function VhuWCntc(sUYKI) {var aVZqqVYH=CuUGfjEaxqHEYNlqDrzZn[13];for(var HwzjK=0;HwzjK<sUYKI;HwzjK++){XFCay+=aVZqqVYH.charAt(Mat" ascii
    $s4  = "function VhuWCntc(sUYKI) {var aVZqqVYH=CuUGfjEaxqHEYNlqDrzZn[13];for(var HwzjK=0;HwzjK<sUYKI;HwzjK++){XFCay+=aVZqqVYH.charAt(Mat" ascii
    $s5  = "function amXDWCiT(GsDbfWtih) {GsDbfWtih.type=1;}" fullword ascii
    $s6  = "function LIliL(dUjAeI){return new ActiveXObject(dUjAeI);}" fullword ascii
    $s7  = "function jAEhGNfOlkZoB() {adHWMvvTkt().Sleep(2392157-568);}" fullword ascii
    $s8  = "if(AJpH>YXtbZ.length) break;" fullword ascii
    $s9  = "function Exmp(GyXLHci,bITSDoL) {GyXLHci.saveToFile(bITSDoL, 2);}" fullword ascii
    $s10 = "function cUvVrDb(){return Math.random();}" fullword ascii
    $s11 = "function UZAa(yCzWcS) {yCzWcS.open();}" fullword ascii
    $s12 = "function sMmaD(AvrEvZum,pJBCJ,UkugGXnRMe){UZAa(AvrEvZum);amXDWCiT(AvrEvZum);NeFgsHk(AvrEvZum,pJBCJ);YVHxSqJhp(AvrEvZum);Exmp(Avr" ascii
    $s13 = "function LQKp(grtKzQ,laZpobK){uwNz = CuUGfjEaxqHEYNlqDrzZn[10].split(CuUGfjEaxqHEYNlqDrzZn[11]);laZpobK.open(uwNz[0]+uwNz[2]+uwN" ascii
    $s14 = "function adHWMvvTkt() {return/*iXodyYEhKOyKxWmQfAZlRQCxtvmWUNLsYfJOtuQPFVHxEeCOPuXZlJEebYcfTbBpxGOWdTAYmMQQSLvdLhKfrXNsQmwpsWfYy" ascii
    $s15 = "function LQKp(grtKzQ,laZpobK){uwNz = CuUGfjEaxqHEYNlqDrzZn[10].split(CuUGfjEaxqHEYNlqDrzZn[11]);laZpobK.open(uwNz[0]+uwNz[2]+uwN" ascii
    $s16 = "function sMmaD(AvrEvZum,pJBCJ,UkugGXnRMe){UZAa(AvrEvZum);amXDWCiT(AvrEvZum);NeFgsHk(AvrEvZum,pJBCJ);YVHxSqJhp(AvrEvZum);Exmp(Avr" ascii
    $s17 = "function YVHxSqJhp(sOJkOG) {var mQrdIbweYh=[];sOJkOG.position=mQrdIbweYh.length*(766880-256);}" fullword ascii
    $s18 = "function KkbytrG(jbQmT) {jbQmT.close();}" fullword ascii
    $s19 = "z[3], grtKzQ, false);laZpobK.send();}" fullword ascii
    $s20 = "lAhwB<TenJhx.length;VCDlAhwB++) {rfsryzD+=hBAme[TenJhx[VCDlAhwB]];}return rfsryzD.substring(3,rfsryzD.length);}" fullword ascii

  condition:
    uint16(0) == 0x1727 and
    8 of them
}