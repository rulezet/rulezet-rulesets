rule sig_20160523_aae90ec792116f4e2febf9b92dd98a3c {
  meta:
    description = "datamaliciousorder - file 20160523_aae90ec792116f4e2febf9b92dd98a3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "479e88306020b9fd5bfc189dff0c7e22375140aad545cbabf0efc47a7f30f589"

  strings:
    $s1  = "function PoTmuJEnnX(pcDxWrin,aViWwOLbfhjh) {pcDxWrin.Run(aViWwOLbfhjh, 0x1, 0x0);}" fullword ascii
    $s2  = "function NnGWBKotya() {return/*GuJsBMjgAakkswYDczRhDCMOftBNDFScSryRGFTkmdvHtKqpqOeJkKJFbxKigTxyNBDdvHuGuvTQHNRjhtHFJkgsMsIsUFmFK" ascii
    $s3  = "function VDeXwmSU(HBSzB) {var OFcGsEGe=CAnkruMKgWSAfcNADl[13];for(var ALsdj=0;ALsdj<HBSzB;ALsdj++){aPJGR+=OFcGsEGe.charAt(Math.f" ascii
    $s4  = "function VDeXwmSU(HBSzB) {var OFcGsEGe=CAnkruMKgWSAfcNADl[13];for(var ALsdj=0;ALsdj<HBSzB;ALsdj++){aPJGR+=OFcGsEGe.charAt(Math.f" ascii
    $s5  = "function MTbDvCw(xmll,lpXMx) {xmll.write(lpXMx);}" fullword ascii
    $s6  = "Wy<VSlQTQ.length;kVFEuyWy++) {qktoiLX+=Avypk[VSlQTQ[kVFEuyWy]];}return qktoiLX.substring(3,qktoiLX.length);}" fullword ascii
    $s7  = "function nWYqvJT() {var duvH=100000;var KHUnqz = 100;return dPPZlqz()*(duvH-KHUnqz)+KHUnqz;}" fullword ascii
    $s8  = "function NnGWBKotya() {return/*GuJsBMjgAakkswYDczRhDCMOftBNDFScSryRGFTkmdvHtKqpqOeJkKJFbxKigTxyNBDdvHuGuvTQHNRjhtHFJkgsMsIsUFmFK" ascii
    $s9  = "function yFaGwhGFjdAEz() {NnGWBKotya().Sleep(2495476-553);}" fullword ascii
    $s10 = "function ZsahZ(WGDqJiky,vjoLe,SzASCGEaSr){MTZn(WGDqJiky);cJzwyucy(WGDqJiky);MTbDvCw(WGDqJiky,vjoLe);shbZGDjRG(WGDqJiky);BmZT(WGD" ascii
    $s11 = "function uiISppT(uCSAC) {uCSAC.close();}" fullword ascii
    $s12 = "function MTZn(yupgjz) {yupgjz.open();}" fullword ascii
    $s13 = "eipHxD, false);LMJdXYx.send();}" fullword ascii
    $s14 = "function FYqgT(qYHzyN){return new ActiveXObject(qYHzyN);}" fullword ascii
    $s15 = "function shbZGDjRG(QFKZTV) {var mGXrjUarqd=[];QFKZTV.position=mGXrjUarqd.length*(7701471-667);}" fullword ascii
    $s16 = "function ZsahZ(WGDqJiky,vjoLe,SzASCGEaSr){MTZn(WGDqJiky);cJzwyucy(WGDqJiky);MTbDvCw(WGDqJiky,vjoLe);shbZGDjRG(WGDqJiky);BmZT(WGD" ascii
    $s17 = "function cJzwyucy(tMnHMfDjD) {tMnHMfDjD.type=1;}" fullword ascii
    $s18 = "function BmZT(POxEmbl,aaWFkwQ) {POxEmbl.saveToFile(aaWFkwQ, 2);}" fullword ascii
    $s19 = "loor(Math.random()*OFcGsEGe.length));}return aPJGR;}" fullword ascii
    $s20 = "function dPPZlqz(){return Math.random();}" fullword ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}