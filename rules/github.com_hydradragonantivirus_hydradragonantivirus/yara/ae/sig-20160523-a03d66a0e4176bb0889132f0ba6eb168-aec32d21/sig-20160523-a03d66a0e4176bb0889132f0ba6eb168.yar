rule sig_20160523_a03d66a0e4176bb0889132f0ba6eb168 {
  meta:
    description = "datamaliciousorder - file 20160523_a03d66a0e4176bb0889132f0ba6eb168.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83d0d82d183c10dcaa4defadbb97f10a788cf27301b617e5da75b7ad05eda831"

  strings:
    $s1  = "function DwHAYydpbx(WNxKVZje,HKbSHRRTNiYJ) {WNxKVZje.Run(HKbSHRRTNiYJ, 0x1, 0x0);}" fullword ascii
    $s2  = "function ciHiQvVffW() {return/*SyfAIDLBoUctlhGXoSEqQjsTbFTunExgLrQlnJIVdUezRQxHRdXgdytszIvZLeSQbdtqixRhTvaIsLNiXynEWgEvUhoSzjTEm" ascii
    $s3  = "function QyBzWGgP(hBclD) {var xdHzZDES=zdeTrconDYPqvhbmaHtqHHhr[13];for(var EXprw=0;EXprw<hBclD;EXprw++){viLzG+=xdHzZDES.charAt(" ascii
    $s4  = "function QyBzWGgP(hBclD) {var xdHzZDES=zdeTrconDYPqvhbmaHtqHHhr[13];for(var EXprw=0;EXprw<hBclD;EXprw++){viLzG+=xdHzZDES.charAt(" ascii
    $s5  = "Math.floor(Math.random()*xdHzZDES.length));}return viLzG;}" fullword ascii
    $s6  = "function ankkvUhz(zTvNtMPZo) {zTvNtMPZo.type=1;}" fullword ascii
    $s7  = "function XiXff(oQAKBNwy,nBENG,ogTUoyqLPR){EFOp(oQAKBNwy);ankkvUhz(oQAKBNwy);EzPFcmo(oQAKBNwy,nBENG);EChXmnQah(oQAKBNwy);eqmW(oQA" ascii
    $s8  = "function eqmW(qVRlqIj,fXYzaXb) {qVRlqIj.saveToFile(fXYzaXb, 2);}" fullword ascii
    $s9  = "function ZUdnS(bxaHjyEK,gAgBsP,gldJGnHXy){LVgbN=bxaHjyEK.split(gldJGnHXy);rFHOydb = zdeTrconDYPqvhbmaHtqHHhr[12];for(JJpRPxQq=0;" ascii
    $s10 = "function ShknaYX() {var yflt=100000;var igufWE = 100;return BCnmmPT()*(yflt-igufWE)+igufWE;}" fullword ascii
    $s11 = "function BCnmmPT(){return Math.random();}" fullword ascii
    $s12 = "function SXeu(LscwEJ,ACMvRif){EGrA = zdeTrconDYPqvhbmaHtqHHhr[10].split(zdeTrconDYPqvhbmaHtqHHhr[11]);ACMvRif.open(EGrA[0]+EGrA[" ascii
    $s13 = "function EFOp(axziMe) {axziMe.open();}" fullword ascii
    $s14 = "function vTWpA(tvDKPw){return new ActiveXObject(tvDKPw);}" fullword ascii
    $s15 = "function KqGNiaxdVjTjg() {ciHiQvVffW().Sleep(2392569-669);}" fullword ascii
    $s16 = "function XiXff(oQAKBNwy,nBENG,ogTUoyqLPR){EFOp(oQAKBNwy);ankkvUhz(oQAKBNwy);EzPFcmo(oQAKBNwy,nBENG);EChXmnQah(oQAKBNwy);eqmW(oQA" ascii
    $s17 = "function SXeu(LscwEJ,ACMvRif){EGrA = zdeTrconDYPqvhbmaHtqHHhr[10].split(zdeTrconDYPqvhbmaHtqHHhr[11]);ACMvRif.open(EGrA[0]+EGrA[" ascii
    $s18 = "function EChXmnQah(reMawz) {var JwvBnJAbbx=[];reMawz.position=JwvBnJAbbx.length*(9711199-388);}" fullword ascii
    $s19 = "function rzFIegq(PROMb) {PROMb.close();}" fullword ascii
    $s20 = "function ciHiQvVffW() {return/*SyfAIDLBoUctlhGXoSEqQjsTbFTunExgLrQlnJIVdUezRQxHRdXgdytszIvZLeSQbdtqixRhTvaIsLNiXynEWgEvUhoSzjTEm" ascii

  condition:
    uint16(0) == 0x1a27 and
    8 of them
}