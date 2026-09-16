rule sig_20160523_169c31c1aaf9bb15c8f91dc1b431f7bb {
  meta:
    description = "datamaliciousorder - file 20160523_169c31c1aaf9bb15c8f91dc1b431f7bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db5832b893f68e8fc098c7e108346fffa8d48678bdead4f161ac6ed73673bb50"

  strings:
    $s1  = "function JyNWlHSXYU(nZzXqyVa,SvPPlmmCoXSX) {nZzXqyVa.Run(SvPPlmmCoXSX, 0x1, 0x0);}" fullword ascii
    $s2  = "function wXHcXLZt(ElEgB) {var nxVBkaSP=cUuYsMsqoguBdeZvknosi[13];for(var UozcI=0;UozcI<ElEgB;UozcI++){JYzsl+=nxVBkaSP.charAt(Mat" ascii
    $s3  = "function wXHcXLZt(ElEgB) {var nxVBkaSP=cUuYsMsqoguBdeZvknosi[13];for(var UozcI=0;UozcI<ElEgB;UozcI++){JYzsl+=nxVBkaSP.charAt(Mat" ascii
    $s4  = "function WxNxYX(vFpvEo){return vFpvEo.ExpandEnvironmentStrings(cUuYsMsqoguBdeZvknosi[9])}" fullword ascii
    $s5  = "function UbEin(vFpvEo){return new ActiveXObject(vFpvEo);}" fullword ascii
    $s6  = "function eHCKsDb(){return Math.random();}" fullword ascii
    $s7  = "function FYNt(sUPsqE) {sUPsqE.open();}" fullword ascii
    $s8  = "function NhrcozMK(wFuDPjGdz) {wFuDPjGdz.type=1;}" fullword ascii
    $s9  = "function NLqHoYE(zlifW) {zlifW.close();}" fullword ascii
    $s10 = "if(LMSa>plPgp.length) break;" fullword ascii
    $s11 = "YdrlC<cpKriw.length;kfpYdrlC++) {NpkJUIK+=fIwhX[cpKriw[kfpYdrlC]];}return NpkJUIK.substring(3,NpkJUIK.length);}" fullword ascii
    $s12 = "h.floor(Math.random()*nxVBkaSP.length));}return JYzsl;}" fullword ascii
    $s13 = "function KkzuR(bVgaVmDq,cpKriw,ZjzAuwLRu){fIwhX=bVgaVmDq.split(ZjzAuwLRu);NpkJUIK = cUuYsMsqoguBdeZvknosi[12];for(kfpYdrlC=0;kfp" ascii
    $s14 = "function sCBnSRV() {var irrG=100000;var xTpBhe = 100;return eHCKsDb()*(irrG-xTpBhe)+xTpBhe;}" fullword ascii
    $s15 = "function Zlfp(NyUkiq,MLWhfWo){OYwV = cUuYsMsqoguBdeZvknosi[10].split(cUuYsMsqoguBdeZvknosi[11]);MLWhfWo.open(OYwV[0]+OYwV[2]+OYw" ascii
    $s16 = "V[3], NyUkiq, false);MLWhfWo.send();}" fullword ascii
    $s17 = "function eRXOA(uwgCjKvv,aKmQl,WKZKstGMvt){FYNt(uwgCjKvv);NhrcozMK(uwgCjKvv);zpkejLv(uwgCjKvv,aKmQl);BFQYfCeCk(uwgCjKvv);Dtta(uwg" ascii
    $s18 = "function Zlfp(NyUkiq,MLWhfWo){OYwV = cUuYsMsqoguBdeZvknosi[10].split(cUuYsMsqoguBdeZvknosi[11]);MLWhfWo.open(OYwV[0]+OYwV[2]+OYw" ascii
    $s19 = "function zpkejLv(JCOK,UmOAP) {JCOK.write(UmOAP);}" fullword ascii
    $s20 = "function KkzuR(bVgaVmDq,cpKriw,ZjzAuwLRu){fIwhX=bVgaVmDq.split(ZjzAuwLRu);NpkJUIK = cUuYsMsqoguBdeZvknosi[12];for(kfpYdrlC=0;kfp" ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}