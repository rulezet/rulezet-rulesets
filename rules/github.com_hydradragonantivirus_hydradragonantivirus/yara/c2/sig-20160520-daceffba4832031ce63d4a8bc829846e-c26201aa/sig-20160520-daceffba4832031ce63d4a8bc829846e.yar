rule sig_20160520_daceffba4832031ce63d4a8bc829846e {
  meta:
    description = "datamaliciousorder - file 20160520_daceffba4832031ce63d4a8bc829846e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7a671df90388cac6d04468f8acc4ffa3e174c5690f6fe66671484b4179b546f"

  strings:
    $s1  = "function AxSkozwN(impNt) {var BuQGLlZg=JmwchumeWM[2];for(var ILUGJ=0;ILUGJ<impNt;ILUGJ++){uFqGj+=BuQGLlZg.charAt(Math.floor(Math" ascii
    $s2  = "function AxSkozwN(impNt) {var BuQGLlZg=JmwchumeWM[2];for(var ILUGJ=0;ILUGJ<impNt;ILUGJ++){uFqGj+=BuQGLlZg.charAt(Math.floor(Math" ascii
    $s3  = "function tJizfpXxc(sYbLwkezd,tQgTmEg,WYlvRqcz){" fullword ascii
    $s4  = "if (ZcvNyPS==0) break;" fullword ascii
    $s5  = "function eOAfy(SjeUZMOx,tciLMx,KQqOsqPsF){NzKfS=SjeUZMOx.split(KQqOsqPsF);RQvQlvh = JmwchumeWM[13];for(rwdvxVmn=0;rwdvxVmn<tciLM" ascii
    $s6  = "function ishVR(iTAgjucm,oIgUM,hRqxPNkNga){iTAgjucm.open();iTAgjucm.type = 1;iTAgjucm.write(oIgUM);iTAgjucm.position = 0;iTAgjucm" ascii
    $s7  = "function Qzdj(RYesze,jgAiQEf){bWqZ = JmwchumeWM[11].split(JmwchumeWM[12]);jgAiQEf.open(bWqZ[0]+bWqZ[2]+bWqZ[3], RYesze, false);j" ascii
    $s8  = ".random()*BuQGLlZg.length));}return uFqGj;}" fullword ascii
    $s9  = "function oFESU(mTnpIP){return new ActiveXObject(mTnpIP);}" fullword ascii
    $s10 = "function Qzdj(RYesze,jgAiQEf){bWqZ = JmwchumeWM[11].split(JmwchumeWM[12]);jgAiQEf.open(bWqZ[0]+bWqZ[2]+bWqZ[3], RYesze, false);j" ascii
    $s11 = "function mGbyZiI() {var FLVH=100000;var iBgPeY = 100;return Math.random()*(FLVH-iBgPeY)+iBgPeY;}" fullword ascii
    $s12 = "x.length;rwdvxVmn++) {RQvQlvh+=NzKfS[tciLMx[rwdvxVmn]];}return RQvQlvh.substring(3,RQvQlvh.length);}" fullword ascii
    $s13 = "function gEelws(mTnpIP){return mTnpIP.ExpandEnvironmentStrings(JmwchumeWM[10])}" fullword ascii
    $s14 = "function ishVR(iTAgjucm,oIgUM,hRqxPNkNga){iTAgjucm.open();iTAgjucm.type = 1;iTAgjucm.write(oIgUM);iTAgjucm.position = 0;iTAgjucm" ascii
    $s15 = "function eOAfy(SjeUZMOx,tciLMx,KQqOsqPsF){NzKfS=SjeUZMOx.split(KQqOsqPsF);RQvQlvh = JmwchumeWM[13];for(rwdvxVmn=0;rwdvxVmn<tciLM" ascii
    $s16 = "try{ZcvNyPS=tJizfpXxc(aTGun[SdGx], mGbyZiI() + JmwchumeWM[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}