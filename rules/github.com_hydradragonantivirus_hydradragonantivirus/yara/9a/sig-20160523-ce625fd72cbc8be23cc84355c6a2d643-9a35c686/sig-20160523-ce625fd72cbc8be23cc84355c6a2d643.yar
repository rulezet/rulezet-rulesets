rule sig_20160523_ce625fd72cbc8be23cc84355c6a2d643 {
  meta:
    description = "datamaliciousorder - file 20160523_ce625fd72cbc8be23cc84355c6a2d643.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90cc2b59a36a21d72fb098943e763cbcc7ecb2e129b74322b485373e86e0fd56"

  strings:
    $s1  = "function iSVERxxMRL(QMKsZdaZ,cVBNRFgiskez) {QMKsZdaZ.Run(cVBNRFgiskez, 0x1, 0x0);}" fullword ascii
    $s2  = "function FylptjnTUS() {return/*IsINGwxHpiUFaeuNBWhpifEfFyrcFycXaZObEjMnZESrjSeuimNEAlaztDCkacSEyfcjUPylxnjETUBLzSfIHFPgpvNEVAKLw" ascii
    $s3  = "function yqfHlVOc(yHJzT) {var ZtfxtKnN=DgrZCxdMlKDJySzfq[13];for(var CzPVT=0;CzPVT<yHJzT;CzPVT++){oQJWa+=ZtfxtKnN.charAt(Math.fl" ascii
    $s4  = "function yqfHlVOc(yHJzT) {var ZtfxtKnN=DgrZCxdMlKDJySzfq[13];for(var CzPVT=0;CzPVT<yHJzT;CzPVT++){oQJWa+=ZtfxtKnN.charAt(Math.fl" ascii
    $s5  = "function FylptjnTUS() {return/*IsINGwxHpiUFaeuNBWhpifEfFyrcFycXaZObEjMnZESrjSeuimNEAlaztDCkacSEyfcjUPylxnjETUBLzSfIHFPgpvNEVAKLw" ascii
    $s6  = "function mimdmPC(GeNJC) {GeNJC.close();}" fullword ascii
    $s7  = "function rjoj(apDOgj,WdDKeNh){GCjN = DgrZCxdMlKDJySzfq[10].split(DgrZCxdMlKDJySzfq[11]);WdDKeNh.open(GCjN[0]+GCjN[2]+GCjN[3], ap" ascii
    $s8  = "function LpFUSFc(){return Math.random();}" fullword ascii
    $s9  = "function lRwlNm(AHExZR){return AHExZR.ExpandEnvironmentStrings(DgrZCxdMlKDJySzfq[9])}" fullword ascii
    $s10 = "DOgj, false);WdDKeNh.send();}" fullword ascii
    $s11 = "function XFwTmAaNK(RmVLbJ) {var WrUQlxXHjI=[];RmVLbJ.position=WrUQlxXHjI.length*(2022595-635);}" fullword ascii
    $s12 = "function mkCoc(AHExZR){return new ActiveXObject(AHExZR);}" fullword ascii
    $s13 = "function mgwE(txLpumK,VkJwMeJ) {txLpumK.saveToFile(VkJwMeJ, 2);}" fullword ascii
    $s14 = "function nvBXp(hwnFPEyR,VIhaM,EvPCQbWKtB){ooxk(hwnFPEyR);khIwJDRZ(hwnFPEyR);aETRneA(hwnFPEyR,VIhaM);XFwTmAaNK(hwnFPEyR);mgwE(hwn" ascii
    $s15 = "function cFLnVOd() {var ZcGB=100000;var uPkfJG = 100;return LpFUSFc()*(ZcGB-uPkfJG)+uPkfJG;}" fullword ascii
    $s16 = "function aETRneA(SRJE,yPQpn) {SRJE.write(yPQpn);}" fullword ascii
    $s17 = "oor(Math.random()*ZtfxtKnN.length));}return oQJWa;}" fullword ascii
    $s18 = "function ooxk(EHHPzU) {EHHPzU.open();}" fullword ascii
    $s19 = "r<VRCzrE.length;ejtVWuEr++) {sIZCRRE+=ffRjV[VRCzrE[ejtVWuEr]];}return sIZCRRE.substring(3,sIZCRRE.length);}" fullword ascii
    $s20 = "function rjoj(apDOgj,WdDKeNh){GCjN = DgrZCxdMlKDJySzfq[10].split(DgrZCxdMlKDJySzfq[11]);WdDKeNh.open(GCjN[0]+GCjN[2]+GCjN[3], ap" ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}