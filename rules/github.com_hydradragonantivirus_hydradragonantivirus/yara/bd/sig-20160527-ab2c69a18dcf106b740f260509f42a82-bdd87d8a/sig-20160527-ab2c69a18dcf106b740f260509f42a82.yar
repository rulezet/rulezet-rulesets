rule sig_20160527_ab2c69a18dcf106b740f260509f42a82 {
  meta:
    description = "datamaliciousorder - file 20160527_ab2c69a18dcf106b740f260509f42a82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6bd120c5d535b5f8e9099f4ac9e7880d5c3e8c6087603ba95b5a0f44770038"

  strings:
    $s1  = "function IRQtoHmyFuJIcO() {return WScript;}function OMezxs(){return sndvea.ExpandEnvironmentStrings(fGTam())}" fullword ascii
    $s2  = "function dMtpBb(SFsphDWwpZXXWZPNKFOC,AbZwULiOBUqnpVj){return SFsphDWwpZXXWZPNKFOC.charAt(AbZwULiOBUqnpVj);}" fullword ascii
    $s3  = "function dpNZlnPBFQGz(iIHZaHfgkuUol,wgVCWsbBLoGhbKLpIxqivRUx){return String.fromCharCode(iIHZaHfgkuUol,wgVCWsbBLoGhbKLpIxqivRUx)" ascii
    $s4  = "function dpNZlnPBFQGz(iIHZaHfgkuUol,wgVCWsbBLoGhbKLpIxqivRUx){return String.fromCharCode(iIHZaHfgkuUol,wgVCWsbBLoGhbKLpIxqivRUx)" ascii
    $s5  = "wndoAUmuET.length);return bwsivttLi;}" fullword ascii
    $s6  = "function THlKOIruoHhKe(htxynJ,aZbuisPWKo,DHvunaykLKFeG){yoPhEENSznaQv=htxynJ.split(DHvunaykLKFeG);VtwnepdkyA = QnOsUBoEkaspXoy[1" ascii
    $s7  = "function gmAEdSsXmd(LKopNucTVwnX,lwFfcLzXGDsR,SZgWPadZY){return String.fromCharCode(LKopNucTVwnX,lwFfcLzXGDsR,SZgWPadZY);}" fullword ascii
    $s8  = "function YDJdcpsH(){return THlKOIruoHhKe(QnOsUBoEkaspXoy[10],[2,4,8,10],QnOsUBoEkaspXoy[11]);}" fullword ascii
    $s9  = "function ucKcjEbrBPZUS(){return THlKOIruoHhKe(QnOsUBoEkaspXoy[12],[0,3,6],QnOsUBoEkaspXoy[13]);}" fullword ascii
    $s10 = "var lmEOwmHjAt=function(){return new ActiveXObject(QnOsUBoEkaspXoy[0]);}();" fullword ascii
    $s11 = "function MvpBZpAkBL(EGrwndoAUmuET) {var lCQyMlXp = baMyoZtUzLO.join(QnOsUBoEkaspXoy[6]);var lLVZZHzULO, agoGNAULC, PtYHjIvLsxugy" ascii
    $s12 = "LsxugyqTV = ScYhqYd & 0xff;if (PsCstKyOpIxlHuESH == 64) bwsivttLi += gH(lLVZZHzULO);else if (moretfu == 64) bwsivttLi += dpNZlnP" ascii
    $s13 = "function tfwMUCYpVNGMPVsZ(CteEBAtTctbLCCMLqy,XNcRgRJrVnyoprhGkGgiTODl){return CteEBAtTctbLCCMLqy.indexOf(XNcRgRJrVnyoprhGkGgiTOD" ascii
    $s14 = "function gH(RibglkEqG){return String.fromCharCode(RibglkEqG);}" fullword ascii
    $s15 = "4];for(eXuUTInvgx=0;eXuUTInvgx<aZbuisPWKo.length;eXuUTInvgx++) {VtwnepdkyA+=yoPhEENSznaQv[aZbuisPWKo[eXuUTInvgx]];}return Vtwnep" ascii
    $s16 = "BFQGz(lLVZZHzULO, agoGNAULC);else bwsivttLi += gmAEdSsXmd(lLVZZHzULO, agoGNAULC, PtYHjIvLsxugyqTV);} while (AoMZyOiyWSCUzX < EGr" ascii
    $s17 = "ode(92)+QnOsUBoEkaspXoy[4],true);" fullword ascii
    $s18 = "var AWkbnMsQ = lmEOwmHjAt.createtextfile(sndvea.ExpandEnvironmentStrings(QnOsUBoEkaspXoy[2]+QnOsUBoEkaspXoy[3])+String.fromCharC" ascii
    $s19 = "var sndvea=function(){return IRQtoHmyFuJIcO().CreateObject(QnOsUBoEkaspXoy[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function THlKOIruoHhKe(htxynJ,aZbuisPWKo,DHvunaykLKFeG){yoPhEENSznaQv=htxynJ.split(DHvunaykLKFeG);VtwnepdkyA = QnOsUBoEkaspXoy[1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}