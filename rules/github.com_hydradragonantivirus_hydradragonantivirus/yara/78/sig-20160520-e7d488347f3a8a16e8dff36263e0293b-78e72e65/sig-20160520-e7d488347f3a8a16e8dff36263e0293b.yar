rule sig_20160520_e7d488347f3a8a16e8dff36263e0293b {
  meta:
    description = "datamaliciousorder - file 20160520_e7d488347f3a8a16e8dff36263e0293b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0526c64884bc4a19c0304666c67baae7a556063401e2e37a82d06318892a2644"

  strings:
    $s1  = "function UMRzrqkI(JdmTs) {var ciWrUKkf=pxquJWYhj[2];for(var JdBFa=0;JdBFa<JdmTs;JdBFa++){YnrYH+=ciWrUKkf.charAt(Math.floor(Math." ascii
    $s2  = "function UMRzrqkI(JdmTs) {var ciWrUKkf=pxquJWYhj[2];for(var JdBFa=0;JdBFa<JdmTs;JdBFa++){YnrYH+=ciWrUKkf.charAt(Math.floor(Math." ascii
    $s3  = "function tVIjFDC() {var dhlk=100000;var MqrLvZ = 100;return Math.random()*(dhlk-MqrLvZ)+MqrLvZ;}" fullword ascii
    $s4  = "function kTJQq(YXOQMunh,olfoh,iIKywOtRMO){YXOQMunh.open();YXOQMunh.type = 1;YXOQMunh.write(olfoh);YXOQMunh.position = 0;YXOQMunh" ascii
    $s5  = "random()*ciWrUKkf.length));}return YnrYH;}" fullword ascii
    $s6  = "if (pzQSHAe==0) break;" fullword ascii
    $s7  = "function NqqB(QBTscD,Hfuaqhr){XgoR = pxquJWYhj[11].split(pxquJWYhj[12]);Hfuaqhr.open(XgoR[0]+XgoR[2]+XgoR[3], QBTscD, false);Hfu" ascii
    $s8  = "function NqqB(QBTscD,Hfuaqhr){XgoR = pxquJWYhj[11].split(pxquJWYhj[12]);Hfuaqhr.open(XgoR[0]+XgoR[2]+XgoR[3], QBTscD, false);Hfu" ascii
    $s9  = "function QSHfu(vaVRnmqz,UuCjpf,roUwTGJZV){asxDN=vaVRnmqz.split(roUwTGJZV);DRKxqWw = pxquJWYhj[13];for(CgTGUjIO=0;CgTGUjIO<UuCjpf" ascii
    $s10 = "function QfSsN(QYkpFJ){return new ActiveXObject(QYkpFJ);}" fullword ascii
    $s11 = "function kTJQq(YXOQMunh,olfoh,iIKywOtRMO){YXOQMunh.open();YXOQMunh.type = 1;YXOQMunh.write(olfoh);YXOQMunh.position = 0;YXOQMunh" ascii
    $s12 = "function OQIHMadVz(jAlWpTleD,lELRzXG,witXklxx){" fullword ascii
    $s13 = "try{pzQSHAe=OQIHMadVz(xFoZu[IyNh], tVIjFDC() + pxquJWYhj[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function uQVdjg(QYkpFJ){return QYkpFJ.ExpandEnvironmentStrings(pxquJWYhj[10])}" fullword ascii
    $s15 = "function QSHfu(vaVRnmqz,UuCjpf,roUwTGJZV){asxDN=vaVRnmqz.split(roUwTGJZV);DRKxqWw = pxquJWYhj[13];for(CgTGUjIO=0;CgTGUjIO<UuCjpf" ascii
    $s16 = ".length;CgTGUjIO++) {DRKxqWw+=asxDN[UuCjpf[CgTGUjIO]];}return DRKxqWw.substring(3,DRKxqWw.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}