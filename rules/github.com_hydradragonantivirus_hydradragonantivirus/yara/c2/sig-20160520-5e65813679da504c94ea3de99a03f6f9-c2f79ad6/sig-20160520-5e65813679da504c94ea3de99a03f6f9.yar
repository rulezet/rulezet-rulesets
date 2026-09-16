rule sig_20160520_5e65813679da504c94ea3de99a03f6f9 {
  meta:
    description = "datamaliciousorder - file 20160520_5e65813679da504c94ea3de99a03f6f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c74687b14206f3792eb72c929a6ff2e8b90fed04f0eb70e35f221adecf683605"

  strings:
    $s1  = "function zcIpnLSV(MQJxH) {var JEZjjChd=ZlPIgPjkBXUxkX[2];for(var GcYCT=0;GcYCT<MQJxH;GcYCT++){cfpoa+=JEZjjChd.charAt(Math.floor(" ascii
    $s2  = "function zcIpnLSV(MQJxH) {var JEZjjChd=ZlPIgPjkBXUxkX[2];for(var GcYCT=0;GcYCT<MQJxH;GcYCT++){cfpoa+=JEZjjChd.charAt(Math.floor(" ascii
    $s3  = "HXVdz.length;IpDdQcrV++) {vdwclxN+=khARc[lHXVdz[IpDdQcrV]];}return vdwclxN.substring(3,vdwclxN.length);}" fullword ascii
    $s4  = "Math.random()*JEZjjChd.length));}return cfpoa;}" fullword ascii
    $s5  = "false);kAkLKwk.send();}" fullword ascii
    $s6  = "function eetkGcoUR(jKuPKyMgr,YrToakI,oXNFCHbm){" fullword ascii
    $s7  = "function ggxwOE(NsmcSy){return NsmcSy.ExpandEnvironmentStrings(ZlPIgPjkBXUxkX[10])}" fullword ascii
    $s8  = "function KSGZh(NsmcSy){return new ActiveXObject(NsmcSy);}" fullword ascii
    $s9  = "function rVai(scirbJ,kAkLKwk){JOpU = ZlPIgPjkBXUxkX[11].split(ZlPIgPjkBXUxkX[12]);kAkLKwk.open(JOpU[0]+JOpU[2]+JOpU[3], scirbJ, " ascii
    $s10 = "try{eetkGcoUR(rwYdH[zooR], DBnmBJH() + ZlPIgPjkBXUxkX[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function DBnmBJH() {var HxIf=100000;var OUkXgZ = 100;return Math.random()*(HxIf-OUkXgZ)+OUkXgZ;}" fullword ascii
    $s12 = "function rBLYy(CrirmIsp,eQMjd,ucrGyzFNHO){CrirmIsp.open();CrirmIsp.type = 1;CrirmIsp.write(eQMjd);CrirmIsp.position = 0;CrirmIsp" ascii
    $s13 = "function rBLYy(CrirmIsp,eQMjd,ucrGyzFNHO){CrirmIsp.open();CrirmIsp.type = 1;CrirmIsp.write(eQMjd);CrirmIsp.position = 0;CrirmIsp" ascii
    $s14 = "function rVai(scirbJ,kAkLKwk){JOpU = ZlPIgPjkBXUxkX[11].split(ZlPIgPjkBXUxkX[12]);kAkLKwk.open(JOpU[0]+JOpU[2]+JOpU[3], scirbJ, " ascii
    $s15 = "function Mxfgt(zigMYScA,lHXVdz,yJUSJbBLj){khARc=zigMYScA.split(yJUSJbBLj);vdwclxN = ZlPIgPjkBXUxkX[13];for(IpDdQcrV=0;IpDdQcrV<l" ascii
    $s16 = "function Mxfgt(zigMYScA,lHXVdz,yJUSJbBLj){khARc=zigMYScA.split(yJUSJbBLj);vdwclxN = ZlPIgPjkBXUxkX[13];for(IpDdQcrV=0;IpDdQcrV<l" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}