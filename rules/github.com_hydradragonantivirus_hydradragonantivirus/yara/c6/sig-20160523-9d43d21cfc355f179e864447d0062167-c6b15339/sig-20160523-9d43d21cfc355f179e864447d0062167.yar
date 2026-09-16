rule sig_20160523_9d43d21cfc355f179e864447d0062167 {
  meta:
    description = "datamaliciousorder - file 20160523_9d43d21cfc355f179e864447d0062167.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b7de61342af57bd214ecdd352b52c5a24d13e342b084f7405727a1e52afad70"

  strings:
    $s1  = "function hoGQcHyOMg(rtcHOqpK,WSsotJDPjbOn) {rtcHOqpK.Run(WSsotJDPjbOn, 0x1, 0x0);}" fullword ascii
    $s2  = "function AaHkRYTN(cePrE) {var xFNxJave=vqEQFoGgwgnocrX[13];for(var RmgyC=0;RmgyC<cePrE;RmgyC++){bleTD+=xFNxJave.charAt(Math.floo" ascii
    $s3  = "function AaHkRYTN(cePrE) {var xFNxJave=vqEQFoGgwgnocrX[13];for(var RmgyC=0;RmgyC<cePrE;RmgyC++){bleTD+=xFNxJave.charAt(Math.floo" ascii
    $s4  = "UCMOiG.length;nGAqZDJr++) {JGaIqeF+=yESZE[UCMOiG[nGAqZDJr]];}return JGaIqeF.substring(3,JGaIqeF.length);}" fullword ascii
    $s5  = "if(tYvQ>adBuQ.length) break;" fullword ascii
    $s6  = "function fRWDVXvMN(nZkFsr) {var qVqLVHNQsp=[];nZkFsr.position=qVqLVHNQsp.length*(5834741-295);}" fullword ascii
    $s7  = "function zlmS(wPJdCl,qkNbTFE){sDgX = vqEQFoGgwgnocrX[10].split(vqEQFoGgwgnocrX[11]);qkNbTFE.open(sDgX[0]+sDgX[2]+sDgX[3], wPJdCl" ascii
    $s8  = ", false);qkNbTFE.send();}" fullword ascii
    $s9  = "function VyUUl(dtGhLx){return new ActiveXObject(dtGhLx);}" fullword ascii
    $s10 = "function ezIdNvd(wIAJo) {wIAJo.close();}" fullword ascii
    $s11 = "function dBVY(mGwNdT) {mGwNdT.open();}" fullword ascii
    $s12 = "function lbxzQCJ() {var mLeL=100000;var PodGsq = 100;return zDAXUDC()*(mLeL-PodGsq)+PodGsq;}" fullword ascii
    $s13 = "function QhyBQ(GGSjOXLt,JIXuW,yTKGFsmsPM){dBVY(GGSjOXLt);zvIBUSEo(GGSjOXLt);oXTCIlm(GGSjOXLt,JIXuW);fRWDVXvMN(GGSjOXLt);OTyQ(GGS" ascii
    $s14 = "function UlIIS(HvrItaGJ,UCMOiG,umHrQXpnK){yESZE=HvrItaGJ.split(umHrQXpnK);JGaIqeF = vqEQFoGgwgnocrX[12];for(nGAqZDJr=0;nGAqZDJr<" ascii
    $s15 = "function zlmS(wPJdCl,qkNbTFE){sDgX = vqEQFoGgwgnocrX[10].split(vqEQFoGgwgnocrX[11]);qkNbTFE.open(sDgX[0]+sDgX[2]+sDgX[3], wPJdCl" ascii
    $s16 = "function zDAXUDC(){return Math.random();}" fullword ascii
    $s17 = "function OTyQ(YFFJulG,SJwRPVz) {YFFJulG.saveToFile(SJwRPVz, 2);}" fullword ascii
    $s18 = "function QhyBQ(GGSjOXLt,JIXuW,yTKGFsmsPM){dBVY(GGSjOXLt);zvIBUSEo(GGSjOXLt);oXTCIlm(GGSjOXLt,JIXuW);fRWDVXvMN(GGSjOXLt);OTyQ(GGS" ascii
    $s19 = "function KbVlsL(dtGhLx){return dtGhLx.ExpandEnvironmentStrings(vqEQFoGgwgnocrX[9])}" fullword ascii
    $s20 = "function zvIBUSEo(aFYsJEuzm) {aFYsJEuzm.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}