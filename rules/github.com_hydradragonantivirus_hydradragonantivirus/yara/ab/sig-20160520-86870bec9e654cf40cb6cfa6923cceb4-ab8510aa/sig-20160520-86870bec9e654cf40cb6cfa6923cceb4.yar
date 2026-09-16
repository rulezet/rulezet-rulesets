rule sig_20160520_86870bec9e654cf40cb6cfa6923cceb4 {
  meta:
    description = "datamaliciousorder - file 20160520_86870bec9e654cf40cb6cfa6923cceb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cebb1426be3083f3717d27f3927d297a4affe6f8b90596bc4d8e0314d5053e9"

  strings:
    $s1  = "function LzBPvbvi(tiPJy) {var SobaDYyS=UFOWHoUqcyyDvj[2];for(var owKrx=0;owKrx<tiPJy;owKrx++){OXqeF+=SobaDYyS.charAt(Math.floor(" ascii
    $s2  = "function LzBPvbvi(tiPJy) {var SobaDYyS=UFOWHoUqcyyDvj[2];for(var owKrx=0;owKrx<tiPJy;owKrx++){OXqeF+=SobaDYyS.charAt(Math.floor(" ascii
    $s3  = "GHotJ.length;LAwcVVkS++) {OqKvKsI+=OjgrI[OGHotJ[LAwcVVkS]];}return OqKvKsI.substring(3,OqKvKsI.length);}" fullword ascii
    $s4  = "function MnpNi(WXPlWpoV,SdBKO,zuComkVzER){WXPlWpoV.open();WXPlWpoV.type = 1;WXPlWpoV.write(SdBKO);WXPlWpoV.position = 0;WXPlWpoV" ascii
    $s5  = "function MnpNi(WXPlWpoV,SdBKO,zuComkVzER){WXPlWpoV.open();WXPlWpoV.type = 1;WXPlWpoV.write(SdBKO);WXPlWpoV.position = 0;WXPlWpoV" ascii
    $s6  = "Math.random()*SobaDYyS.length));}return OXqeF;}" fullword ascii
    $s7  = "function PZmF(GTutuL,OyEHFMg){mGBB = UFOWHoUqcyyDvj[11].split(UFOWHoUqcyyDvj[12]);OyEHFMg.open(mGBB[0]+mGBB[2]+mGBB[3], GTutuL, " ascii
    $s8  = "function zPMPD(lZbVlNvs,OGHotJ,YzXAdsamk){OjgrI=lZbVlNvs.split(YzXAdsamk);OqKvKsI = UFOWHoUqcyyDvj[13];for(LAwcVVkS=0;LAwcVVkS<O" ascii
    $s9  = "function ANFSk(ERuUNr){return new ActiveXObject(ERuUNr);}" fullword ascii
    $s10 = "function zPMPD(lZbVlNvs,OGHotJ,YzXAdsamk){OjgrI=lZbVlNvs.split(YzXAdsamk);OqKvKsI = UFOWHoUqcyyDvj[13];for(LAwcVVkS=0;LAwcVVkS<O" ascii
    $s11 = "try{SGZCyhLsX(GnPPW[APBZ], UouJSrn() + UFOWHoUqcyyDvj[9], 1)}catch(e){}; " fullword ascii
    $s12 = "false);OyEHFMg.send();}" fullword ascii
    $s13 = "function QymJSm(ERuUNr){return ERuUNr.ExpandEnvironmentStrings(UFOWHoUqcyyDvj[10])}" fullword ascii
    $s14 = "function SGZCyhLsX(AOacfFGYM,jNwOYBI,cXBuVDRP){" fullword ascii
    $s15 = "function UouJSrn() {var zSoR=100000;var vfXeds = 100;return Math.random()*(zSoR-vfXeds)+vfXeds;}" fullword ascii
    $s16 = "function PZmF(GTutuL,OyEHFMg){mGBB = UFOWHoUqcyyDvj[11].split(UFOWHoUqcyyDvj[12]);OyEHFMg.open(mGBB[0]+mGBB[2]+mGBB[3], GTutuL, " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}