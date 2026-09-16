rule sig_20160523_aa484850539e0fda7ff287d6e58c2784 {
  meta:
    description = "datamaliciousorder - file 20160523_aa484850539e0fda7ff287d6e58c2784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "142c572e1fb5e518738cfe16ab879542af5b922954704f0a29e3d22962d1f540"

  strings:
    $s1  = "function PYQvLSFPCq(sSnWNVqP,dSIAYaQjLlKu) {sSnWNVqP.Run(dSIAYaQjLlKu, 0x1, 0x0);}" fullword ascii
    $s2  = "function ZsOrVFxE(DSlZb) {var pVBVITIp=loXkKStNHaFbdbhJZ[13];for(var jYsOB=0;jYsOB<DSlZb;jYsOB++){AdyYs+=pVBVITIp.charAt(Math.fl" ascii
    $s3  = "function ZsOrVFxE(DSlZb) {var pVBVITIp=loXkKStNHaFbdbhJZ[13];for(var jYsOB=0;jYsOB<DSlZb;jYsOB++){AdyYs+=pVBVITIp.charAt(Math.fl" ascii
    $s4  = "function pGPmN(PnIwxpLw,POvsD,bkoZUcOMKv){qpbz(PnIwxpLw);tCpSAhao(PnIwxpLw);SrigcVg(PnIwxpLw,POvsD);NfQlbcPcc(PnIwxpLw);yCmQ(PnI" ascii
    $s5  = "function pGPmN(PnIwxpLw,POvsD,bkoZUcOMKv){qpbz(PnIwxpLw);tCpSAhao(PnIwxpLw);SrigcVg(PnIwxpLw,POvsD);NfQlbcPcc(PnIwxpLw);yCmQ(PnI" ascii
    $s6  = "function TVRYUsr(){return Math.random();}" fullword ascii
    $s7  = "function Zerp(zMfgtU,TUloYeh){fmGM = loXkKStNHaFbdbhJZ[10].split(loXkKStNHaFbdbhJZ[11]);TUloYeh.open(fmGM[0]+fmGM[2]+fmGM[3], zM" ascii
    $s8  = "function xhmAYgN() {var ppwu=100000;var OUjsRN = 100;return TVRYUsr()*(ppwu-OUjsRN)+OUjsRN;}" fullword ascii
    $s9  = "function unRqYM(fsKerU){return fsKerU.ExpandEnvironmentStrings(loXkKStNHaFbdbhJZ[9])}" fullword ascii
    $s10 = "function auYZp(mpdLzBvL,nVSogh,OTjyZxaDS){vKsoJ=mpdLzBvL.split(OTjyZxaDS);GRioQkV = loXkKStNHaFbdbhJZ[12];for(AMKlaWCv=0;AMKlaWC" ascii
    $s11 = "oor(Math.random()*pVBVITIp.length));}return AdyYs;}" fullword ascii
    $s12 = "function mpyvobL(QpDNT) {QpDNT.close();}" fullword ascii
    $s13 = "if(mADa>jOWge.length) break;" fullword ascii
    $s14 = "fgtU, false);TUloYeh.send();}" fullword ascii
    $s15 = "function auYZp(mpdLzBvL,nVSogh,OTjyZxaDS){vKsoJ=mpdLzBvL.split(OTjyZxaDS);GRioQkV = loXkKStNHaFbdbhJZ[12];for(AMKlaWCv=0;AMKlaWC" ascii
    $s16 = "function pbzan(fsKerU){return new ActiveXObject(fsKerU);}" fullword ascii
    $s17 = "v<nVSogh.length;AMKlaWCv++) {GRioQkV+=vKsoJ[nVSogh[AMKlaWCv]];}return GRioQkV.substring(3,GRioQkV.length);}" fullword ascii
    $s18 = "function Zerp(zMfgtU,TUloYeh){fmGM = loXkKStNHaFbdbhJZ[10].split(loXkKStNHaFbdbhJZ[11]);TUloYeh.open(fmGM[0]+fmGM[2]+fmGM[3], zM" ascii
    $s19 = "function tCpSAhao(LNsraXdsQ) {LNsraXdsQ.type=1;}" fullword ascii
    $s20 = "function SrigcVg(vFad,Fhrsl) {vFad.write(Fhrsl);}" fullword ascii

  condition:
    uint16(0) == 0x1727 and
    8 of them
}