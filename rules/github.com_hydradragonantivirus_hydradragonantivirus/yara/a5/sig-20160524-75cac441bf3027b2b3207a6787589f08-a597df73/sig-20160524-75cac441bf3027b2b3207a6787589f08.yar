rule sig_20160524_75cac441bf3027b2b3207a6787589f08 {
  meta:
    description = "datamaliciousorder - file 20160524_75cac441bf3027b2b3207a6787589f08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9409e53bb73fabb7acf58e04970a4967eec6ed02d98180a80d222e8e59a938b8"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "FKbfD.Run(RorLhKGxvlBbYZpgyiI[0]+EglDobzyp,0x1,0x0);}dfmQQIKD();function (TRhilUfHkwQvBS) {return new ActiveXObject(TRhilUfHkwQv" ascii
    $s3  = "A+=oJmBeDau.charAt(Math.floor(Math.random()*oJmBeDau.length));}return NFxUA;}function wMsrFnoSAMpAmx(mpsdyJaQPFMwEE) {return new" ascii
    $s4  = "n new ActiveXObject(ymjvHHSLaPLgpfyjF[0]);}();var FKbfD=function(){return new ActiveXObject(\"WScript.Shell\");}();var xpWnmZeDQ" ascii
    $s5  = "Kph,CiTALzGCWiGz) {thpMcKph.Run(CiTALzGCWiGz, 0x1, 0x0);}function mDfxRKX() {var tAoY=100000;var JSbAQW = 100;return UrGihHF()*(" ascii
    $s6  = "cdUJuQqOXGbSpmuvBSmvl*/WScript;}function kGNWVKEET(fRroJx) {var LRPUTPoitS=[];fRroJx.position=LRPUTPoitS.length*(8262890-176);}f" ascii
    $s7  = "dgxoSJWAFG[1]];var UTuD=680-680;while(true) {if(UTuD>rFIEW.length) break;var CYuKdBaLM=rFIEW[UTuD];var NHeJThN=mDfxRKX() + DYqIl" ascii
    $s8  = ",2,4],DYqIlwBtAfdPdgxoSJWAFG[4]));}();var NHeJThN = oybOSI(xlOQsejvy) + String.fromCharCode(92) + NHeJThN;var BFbDC = function()" ascii
    $s9  = "FSZueia.substring(3,FSZueia.length);}function kWqzApeVzJjFs() {ZhyaoVntFv().Sleep(5195-536);}function UrGihHF(){return Math.rand" ascii
    $s10 = "rite(WaCSm);}function ZhyaoVntFv() {return/*EoqhBXodLfRGlXQQGlDfchVxdvmqOntKOuHbicUpAWzZWnnbaODWSIlGcIEFJZARstrPhaUvJGBkbxfgOkWG" ascii
    $s11 = "om();}function cJPk(gaUGoe) {gaUGoe.open();}function BFQtPrES(pCXZfxMMR) {pCXZfxMMR.type=1;}function PpEDNyz(UfFV,WaCSm) {UfFV.w" ascii
    $s12 = "C.status == 100+100) {var DyrglAU = function() {return new ActiveXObject(YASin(DYqIlwBtAfdPdgxoSJWAFG[7],[0,2,4],DYqIlwBtAfdPdgx" ascii
    $s13 = "P[0]+FyKP[2]+FyKP[3], ubBMPY, false);BdNLaKb.send();}function YASin(apmJNzZR,ANVQxX,WkqvDerZN){lStTd=apmJNzZR.split(WkqvDerZN);F" ascii
    $s14 = "NJ(ZfCTXMzV);}function sbce(ubBMPY,BdNLaKb){FyKP = DYqIlwBtAfdPdgxoSJWAFG[10].split(DYqIlwBtAfdPdgxoSJWAFG[11]);BdNLaKb.open(FyK" ascii
    $s15 = "x6a\\x47\\x58\\x4d\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function dfmQQIKD() {var XGMiOoT;var AacZjOKtKrDGat" ascii
    $s16 = "SZueia = DYqIlwBtAfdPdgxoSJWAFG[12];for(dkbYmgtj=0;dkbYmgtj<ANVQxX.length;dkbYmgtj++) {FSZueia+=lStTd[ANVQxX[dkbYmgtj]];}return " ascii
    $s17 = "wBtAfdPdgxoSJWAFG[2];var xESkjhGu=916-915;var xlOQsejvy = function(){return new ActiveXObject(YASin(DYqIlwBtAfdPdgxoSJWAFG[3],[0" ascii
    $s18 = "fromCharCode(92)+xpWnmZeDQlAJNi;XGMiOoT = AacZjOKtKrDGat.OpenTextFile(EglDobzyp,2,true);XGMiOoT.Write('var DYqIlwBtAfdPdgxoSJWAF" ascii
    $s19 = "{return new ActiveXObject(YASin(DYqIlwBtAfdPdgxoSJWAFG[5],[0,2,4],DYqIlwBtAfdPdgxoSJWAFG[6]));}();sbce(CYuKdBaLM,BFbDC);if (BFbD" ascii
    $s20 = "eak;};UTuD++;}function oybOSI(JsERzH){return JsERzH.ExpandEnvironmentStrings(DYqIlwBtAfdPdgxoSJWAFG[9])}function Mflgu(ZfCTXMzV," ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}