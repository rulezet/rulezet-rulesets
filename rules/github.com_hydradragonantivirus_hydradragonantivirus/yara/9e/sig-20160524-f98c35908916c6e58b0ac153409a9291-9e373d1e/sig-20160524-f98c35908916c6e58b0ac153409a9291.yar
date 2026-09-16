rule sig_20160524_f98c35908916c6e58b0ac153409a9291 {
  meta:
    description = "datamaliciousorder - file 20160524_f98c35908916c6e58b0ac153409a9291.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11ccc7c1a5cc6e087113e3f93635dda99ec96df7d0add8eb08c7f73c2a0091c2"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "(){return new ActiveXObject(rUCfELIedvHtkxQBlQPQdoY[0]);}();var MOCNNbLcW=function(){return new ActiveXObject(\"WScript.Shell\")" ascii
    $s3  = "ction vdwclxN(xtIxX) {xtIxX.close();}function mhEOITNIZq(dPcxeVjM,WmnhjyEhXScL) {dPcxeVjM.Run(WmnhjyEhXScL, 0x1, 0x0);}function " ascii
    $s4  = "qw) + String.fromCharCode(92) + DAMKQpi;var BnmBJ = function(){return new ActiveXObject(KUHzo(YCsQucQbMSnNkaOwNbAPOC[5],[0,2,4]," ascii
    $s5  = " break;var BOFMbTPjQ=AxsnT[YrTo];var DAMKQpi=rxTKRkQ() + YCsQucQbMSnNkaOwNbAPOC[2];var cfpILteY=209-208;var agMoPpTqw = function" ascii
    $s6  = "urn nWtQR;}function ruNjHzIuqYIbhR(pSACKdlcxtISIa) {return new ActiveXObject(pSACKdlcxtISIa);}');var hIpiCjHEQZYsJkbTR=[\"\\x77" ascii
    $s7  = "CfdrAUePbmzxjshqCWtQmmcXRWyiwpBxHZBnCosDLSpRpXncRnBIxcZILZYzMqqggNtcXBZlPrzfPvMIAyd*/WScript;}function JxMxfgtzi(gMYScA) {var lH" ascii
    $s8  = ".length;fmmbrBLY++) {mIspeQM+=yCrir[smcSyg[fmmbrBLY]];}return mIspeQM.substring(3,mIspeQM.length);}function ubLrmYVSJwlAJ() {QeY" ascii
    $s9  = "WlK();function (yXGSAkldJ) {return new ActiveXObject(yXGSAkldJ);}" fullword ascii
    $s10 = "pSvjUKA().Sleep(4259-969);}function crGyzFN(){return Math.random();}function HOrV(aiscir) {aiscir.open();}function bJkAkLKw(kJOp" ascii
    $s11 = "Object(KUHzo(YCsQucQbMSnNkaOwNbAPOC[7],[0,2,4],YCsQucQbMSnNkaOwNbAPOC[8]));}();OyyKA(HHxIfOU,BnmBJ.ResponseBody,DAMKQpi);}if (cf" ascii
    $s12 = "wNbAPOC[10].split(YCsQucQbMSnNkaOwNbAPOC[11]);vwfXTyV.open(LfMT[0]+LfMT[2]+LfMT[3], LkzPCP, false);vwfXTyV.send();}function KUHz" ascii
    $s13 = "entStrings(YCsQucQbMSnNkaOwNbAPOC[9])}function OyyKA(hVBlGhbu,YuaaP,tQBjpqWMUQ){hVBlGhbu.open();bJkAkLKw(hVBlGhbu);KBnhjTp(hVBlG" ascii
    $s14 = "2,true);AOvwwQGEwbYYk.Write('var YCsQucQbMSnNkaOwNbAPOC=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x61\\x73\\x75\\x72\\x61\\x6" ascii
    $s15 = "VSJwlAJ();var AxsnT = [YCsQucQbMSnNkaOwNbAPOC[0], YCsQucQbMSnNkaOwNbAPOC[1]];var YrTo=861-861;while(true) {if(YrTo>AxsnT.length)" ascii
    $s16 = "79\\x49\\x54\\x57\\x4a\\x76\\x70\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function vIWlK() {var AOvwwQGEwbYYk;v" ascii
    $s17 = "hbu,YuaaP);JxMxfgtzi(hVBlGhbu);JbBL(hVBlGhbu,tQBjpqWMUQ);vdwclxN(hVBlGhbu);}function ICuk(LkzPCP,vwfXTyV){LfMT = YCsQucQbMSnNkaO" ascii
    $s18 = "YCsQucQbMSnNkaOwNbAPOC[6]));}();ICuk(BOFMbTPjQ,BnmBJ);if (BnmBJ.status == 100+100) {var HHxIfOU = function() {return new ActiveX" ascii
    $s19 = "(){return new ActiveXObject(KUHzo(YCsQucQbMSnNkaOwNbAPOC[3],[0,2,4],YCsQucQbMSnNkaOwNbAPOC[4]));}();var DAMKQpi = PvwLmf(agMoPpT" ascii
    $s20 = "UBbRE) {kJOpUBbRE.type=1;}function KBnhjTp(Wxii,NxZDY) {Wxii.write(NxZDY);}function QeYpSvjUKA() {return/*cXwHvxGzERupxfqOsLAgfH" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}