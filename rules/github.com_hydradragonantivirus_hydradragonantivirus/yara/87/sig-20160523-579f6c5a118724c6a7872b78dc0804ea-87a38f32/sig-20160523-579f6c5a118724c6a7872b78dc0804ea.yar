rule sig_20160523_579f6c5a118724c6a7872b78dc0804ea {
  meta:
    description = "datamaliciousorder - file 20160523_579f6c5a118724c6a7872b78dc0804ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8481fd378eac358cd73cecba31f5d8be0e91ab633bdc7c5192dae3dcd2af7908"

  strings:
    $s1  = "function dMqwelrFMr(wtNvdRso,jDmqnKHqpQoI) {wtNvdRso.Run(jDmqnKHqpQoI, 0x1, 0x0);}" fullword ascii
    $s2  = "function DwfHWkCF(qqlyD) {var MNXbWmmC=NtEbteCJ[13];for(var Umexc=0;Umexc<qqlyD;Umexc++){UKFvN+=MNXbWmmC.charAt(Math.floor(Math." ascii
    $s3  = "function DwfHWkCF(qqlyD) {var MNXbWmmC=NtEbteCJ[13];for(var Umexc=0;Umexc<qqlyD;Umexc++){UKFvN+=MNXbWmmC.charAt(Math.floor(Math." ascii
    $s4  = "function yBgDUlo(){return Math.random();}" fullword ascii
    $s5  = "function UvOtc(rlNKfxBM,JavzC,aGOHdTYymt){DttF(rlNKfxBM);vKhJlGxt(rlNKfxBM);FjCwQpY(rlNKfxBM,JavzC);TKBSRfhzg(rlNKfxBM);YvvF(rlN" ascii
    $s6  = "function lKoHa(xAbhhn){return new ActiveXObject(xAbhhn);}" fullword ascii
    $s7  = "function FjCwQpY(dXAO,Gsrfq) {dXAO.write(Gsrfq);}" fullword ascii
    $s8  = "function WWUEMHZ() {var WsaC=100000;var hYTCRr = 100;return yBgDUlo()*(WsaC-hYTCRr)+hYTCRr;}" fullword ascii
    $s9  = "function zRtjl(yIeDpMXM,kDrxzF,sWaRFUgLi){tUykx=yIeDpMXM.split(sWaRFUgLi);OIYfyrb = NtEbteCJ[12];for(DIlHHYQg=0;DIlHHYQg<kDrxzF." ascii
    $s10 = "function zRtjl(yIeDpMXM,kDrxzF,sWaRFUgLi){tUykx=yIeDpMXM.split(sWaRFUgLi);OIYfyrb = NtEbteCJ[12];for(DIlHHYQg=0;DIlHHYQg<kDrxzF." ascii
    $s11 = "length;DIlHHYQg++) {OIYfyrb+=tUykx[kDrxzF[DIlHHYQg]];}return OIYfyrb.substring(3,OIYfyrb.length);}" fullword ascii
    $s12 = "function vKhJlGxt(sfZfCzmYZ) {sfZfCzmYZ.type=1;}" fullword ascii
    $s13 = "function UvOtc(rlNKfxBM,JavzC,aGOHdTYymt){DttF(rlNKfxBM);vKhJlGxt(rlNKfxBM);FjCwQpY(rlNKfxBM,JavzC);TKBSRfhzg(rlNKfxBM);YvvF(rlN" ascii
    $s14 = "function VYhT(WHSDTw,ZjePGWv){MsCk = NtEbteCJ[10].split(NtEbteCJ[11]);ZjePGWv.open(MsCk[0]+MsCk[2]+MsCk[3], WHSDTw, false);ZjePG" ascii
    $s15 = "if(dEgR>IkBQb.length) break;" fullword ascii
    $s16 = "function DttF(WBKygw) {WBKygw.open();}" fullword ascii
    $s17 = "function gTHAzT(xAbhhn){return xAbhhn.ExpandEnvironmentStrings(NtEbteCJ[9])}" fullword ascii
    $s18 = "function TKBSRfhzg(ACVctR) {var ryJFALUWGH=[];ACVctR.position=ryJFALUWGH.length*(4076323-260);}" fullword ascii
    $s19 = "random()*MNXbWmmC.length));}return UKFvN;}" fullword ascii
    $s20 = "function hZueDKc(axatn) {axatn.close();}" fullword ascii

  condition:
    uint16(0) == 0x0527 and
    8 of them
}