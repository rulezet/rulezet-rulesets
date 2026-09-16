rule sig_20160520_eb23047217a627e57eee7068798a1777 {
  meta:
    description = "datamaliciousorder - file 20160520_eb23047217a627e57eee7068798a1777.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "989a79a40d647d8f734002ee903917a08b4a2b2db178e321de01578100e450ef"

  strings:
    $s1  = "function HFrbNsLf(wrhmZ) {var bKGpvYZK=PZYjbvzNpuUHGjQbI[2];for(var XdDbF=0;XdDbF<wrhmZ;XdDbF++){DcFSE+=bKGpvYZK.charAt(Math.flo" ascii
    $s2  = "function HFrbNsLf(wrhmZ) {var bKGpvYZK=PZYjbvzNpuUHGjQbI[2];for(var XdDbF=0;XdDbF<wrhmZ;XdDbF++){DcFSE+=bKGpvYZK.charAt(Math.flo" ascii
    $s3  = "XNuD, false);zmtKtJS.send();}" fullword ascii
    $s4  = "function haogx(gRqdfZLx,aYiEy,AaWCPfySEO){gRqdfZLx.open();gRqdfZLx.type = 1;gRqdfZLx.write(aYiEy);gRqdfZLx.position = 0;gRqdfZLx" ascii
    $s5  = "O<EiSKRQ.length;gVCwlFbO++) {bjxekBK+=NqLlF[EiSKRQ[gVCwlFbO]];}return bjxekBK.substring(3,bjxekBK.length);}" fullword ascii
    $s6  = "function NGTyg(VSYOjH){return new ActiveXObject(VSYOjH);}" fullword ascii
    $s7  = "function IycT(zaXNuD,zmtKtJS){BSWS = PZYjbvzNpuUHGjQbI[11].split(PZYjbvzNpuUHGjQbI[12]);zmtKtJS.open(BSWS[0]+BSWS[2]+BSWS[3], za" ascii
    $s8  = "or(Math.random()*bKGpvYZK.length));}return DcFSE;}" fullword ascii
    $s9  = "function CCJHb(hwFeamFb,EiSKRQ,fymoCiOiV){NqLlF=hwFeamFb.split(fymoCiOiV);bjxekBK = PZYjbvzNpuUHGjQbI[13];for(gVCwlFbO=0;gVCwlFb" ascii
    $s10 = "function HqpQoIL() {var ZtjA=100000;var QGmivo = 100;return Math.random()*(ZtjA-QGmivo)+QGmivo;}" fullword ascii
    $s11 = "function IycT(zaXNuD,zmtKtJS){BSWS = PZYjbvzNpuUHGjQbI[11].split(PZYjbvzNpuUHGjQbI[12]);zmtKtJS.open(BSWS[0]+BSWS[2]+BSWS[3], za" ascii
    $s12 = "function izAaMXsfe(dIdyIuADf,cBGlDLs,swhYtFwj){" fullword ascii
    $s13 = "function odWpET(VSYOjH){return VSYOjH.ExpandEnvironmentStrings(PZYjbvzNpuUHGjQbI[10])}" fullword ascii
    $s14 = "try{izAaMXsfe(DmqnK[Ttdc], HqpQoIL() + PZYjbvzNpuUHGjQbI[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function haogx(gRqdfZLx,aYiEy,AaWCPfySEO){gRqdfZLx.open();gRqdfZLx.type = 1;gRqdfZLx.write(aYiEy);gRqdfZLx.position = 0;gRqdfZLx" ascii
    $s16 = "function CCJHb(hwFeamFb,EiSKRQ,fymoCiOiV){NqLlF=hwFeamFb.split(fymoCiOiV);bjxekBK = PZYjbvzNpuUHGjQbI[13];for(gVCwlFbO=0;gVCwlFb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}