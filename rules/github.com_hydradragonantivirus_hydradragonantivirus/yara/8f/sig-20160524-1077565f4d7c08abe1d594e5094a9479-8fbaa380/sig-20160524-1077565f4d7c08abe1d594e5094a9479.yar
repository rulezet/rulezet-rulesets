rule sig_20160524_1077565f4d7c08abe1d594e5094a9479 {
  meta:
    description = "datamaliciousorder - file 20160524_1077565f4d7c08abe1d594e5094a9479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b5d767b6c4b2622c49c15e73adfc6634ce84f81ab88b064d5ec2d45c8803910"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "new ActiveXObject(QmTsTtHferHQcqvXj[0]);}();var AEWtcjuDSF=function(){return new ActiveXObject(\"WScript.Shell\");}();var zLbjtO" ascii
    $s3  = "nction(){return new ActiveXObject(uADLr(TTpwHofTeHG[3],[0,2,4],TTpwHofTeHG[4]));}();var AGXbHUo = UONGIz(jAAonbQjf) + String.fro" ascii
    $s4  = "eToFile(FyzQreP, 2);}function LJWTDSQ(KXEfM) {KXEfM.close();}function YdGXlbMROJ(ornOEWMA,AEQEuOFmeyIj) {ornOEWMA.Run(AEQEuOFmey" ascii
    $s5  = "/*aAmchQencBqopsmDZzMfLJftEgmqjCwvEjDHvMYxMwzRiZymOFNHjbJAyyeQlGsaCNofcClBPlcnuAdOWFhbanGAKJrjHEGzUjswckSyl*/WScript;}function K" ascii
    $s6  = "mCharCode(92) + AGXbHUo;var eFGEc = function(){return new ActiveXObject(uADLr(TTpwHofTeHG[5],[0,2,4],TTpwHofTeHG[6]));}();ZewH(p" ascii
    $s7  = "QmB>Pikoo.length) break;var puiKqIzDb=Pikoo[AQmB];var AGXbHUo=maWrQXK() + TTpwHofTeHG[2];var vphCNjMm=912-911;var jAAonbQjf = fu" ascii
    $s8  = "tring.fromCharCode(92)+zLbjtOJr;VFVKgBsnYGH = sCsKTeNNvWQceJ.OpenTextFile(mRIIuzlfSwcyQ,2,true);VFVKgBsnYGH.Write('var TTpwHofTe" ascii
    $s9  = "zCFqLWnd(cSZJRR) {var VtWPHSIlmr=[];cSZJRR.position=VtWPHSIlmr.length*(3795068-473);}function UepD(XSXNKAN,FyzQreP) {XSXNKAN.sav" ascii
    $s10 = "x42\\x74\\x4b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function YWhfFX() {var VFVKgBsnYGH;var sCsKTeNNvWQceJ=fu" ascii
    $s11 = "length));}return iAGSI;}function NMwoGvNENXWjLg(rDHfPLeGHdiWMF) {return new ActiveXObject(rDHfPLeGHdiWMF);}');var kVAeqbMWEFepHP" ascii
    $s12 = "alse);UswIftk.send();}function uADLr(NgVxIKyR,yhrcTP,YlgzsVUEX){Jkkny=NgVxIKyR.split(YlgzsVUEX);rrvngdG = TTpwHofTeHG[12];for(mx" ascii
    $s13 = "break;};AQmB++;}function UONGIz(KgiJVd){return KgiJVd.ExpandEnvironmentStrings(TTpwHofTeHG[9])}function QUDHv(soJmguPA,eTDXD,keP" ascii
    $s14 = "PA);}function ZewH(peQgTR,UswIftk){vxQT = TTpwHofTeHG[10].split(TTpwHofTeHG[11]);UswIftk.open(vxQT[0]+vxQT[2]+vxQT[3], peQgTR, f" ascii
    $s15 = "ion TYDZUcjxzVpkt() {VffIMKAsUJ().Sleep(2835-644);}function tMZnGfa(){return Math.random();}function VRTB(CZFpAC) {CZFpAC.open()" ascii
    $s16 = ";}function uAIySUrm(dItQGBfIH) {dItQGBfIH.type=1;}function MvOJZFE(SABf,NZCNz) {SABf.write(NZCNz);}function VffIMKAsUJ() {return" ascii
    $s17 = "jLQZFzAKjuNzFMbzfuqnuKdWKzmdNgq*/TYDZUcjxzVpkt();var Pikoo = [TTpwHofTeHG[0], TTpwHofTeHG[1]];var AQmB=662-662;while(true) {if(A" ascii
    $s18 = "Ij, 0x1, 0x0);}function maWrQXK() {var YzNW=100000;var GsGxoa = 100;return tMZnGfa()*(YzNW-GsGxoa)+GsGxoa;}function pGuCZpXC(uPv" ascii
    $s19 = "WMPySj=0;mxWMPySj<yhrcTP.length;mxWMPySj++) {rrvngdG+=Jkkny[yhrcTP[mxWMPySj]];}return rrvngdG.substring(3,rrvngdG.length);}funct" ascii
    $s20 = "uiKqIzDb,eFGEc);if (eFGEc.status == 100+100) {var unhIWTO = function() {return new ActiveXObject(uADLr(TTpwHofTeHG[7],[0,2,4],TT" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}