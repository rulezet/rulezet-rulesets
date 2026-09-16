rule sig_20160524_66a149dbbaeebbb64845ce603a6f426a {
  meta:
    description = "datamaliciousorder - file 20160524_66a149dbbaeebbb64845ce603a6f426a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f649d2f9b7508020eae5a61090d453a3ca0bda535a6bba2e8351e121a98e189e"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "){return new ActiveXObject(ncwORcschxSsG[0]);}();var bYfBinfEL=function(){return new ActiveXObject(\"WScript.Shell\");}();var PF" ascii
    $s3  = "STwZEPDgmBOaxPtfoSlurtHrLFzVZmfDpBsojjCBOuCoHVJZUWRHgkpKwVXguPfufdHyixUQJhJwlUtNUVQN*/WScript;}function vgSrClAjV(QNJFfv) {var Q" ascii
    $s4  = "nction CQVtBeS(ssgkK) {ssgkK.close();}function azHNVqutej(lTYiogCT,rxnvFKgsOmCP) {lTYiogCT.Run(rxnvFKgsOmCP, 0x1, 0x0);}function" ascii
    $s5  = "KkCWXoTUcwWK[13];for(var YNeaW=0;YNeaW<svmVy;YNeaW++){HNldd+=jHUYxbOx.charAt(Math.floor(Math.random()*jHUYxbOx.length));}return " ascii
    $s6  = "wWK[4]));}();var YzxYsZB = LfclIY(eZbuorntU) + String.fromCharCode(92) + YzxYsZB;var kCVnE = function(){return new ActiveXObject" ascii
    $s7  = "[1]];var diaz=269-269;while(true) {if(diaz>yHodr.length) break;var UGIOqegyS=yHodr[diaz];var YzxYsZB=assvCIh() + mHcmnKkCWXoTUcw" ascii
    $s8  = "eRSvKc.ExpandEnvironmentStrings(mHcmnKkCWXoTUcwWK[9])}function RsYGa(IKOtbMWB,kvCDu,EFepEDijnu){IKOtbMWB.open();OeuwRPAO(IKOtbMW" ascii
    $s9  = "YLNiRZ) {qasYLNiRZ.type=1;}function KHLFTay(AVZw,lUOxI) {AVZw.write(lUOxI);}function fTCsoYEeBt() {return/*FGDwfbGYbVvsTtivDZEzG" ascii
    $s10 = "WK[2];var ISsdtBOV=919-918;var eZbuorntU = function(){return new ActiveXObject(LdVUF(mHcmnKkCWXoTUcwWK[3],[0,2,4],mHcmnKkCWXoTUc" ascii
    $s11 = " function() {return new ActiveXObject(LdVUF(mHcmnKkCWXoTUcwWK[7],[0,2,4],mHcmnKkCWXoTUcwWK[8]));}();RsYGa(EEsivjo,kCVnE.Response" ascii
    $s12 = "fromCharCode(92)+PFrDxUaWtCHP;NXOcJN = WQzDZyWm.OpenTextFile(rMIdYNbgTUCD,2,true);NXOcJN.Write('var mHcmnKkCWXoTUcwWK=[\"\\x68" ascii
    $s13 = "kQScQiUqa=[];QNJFfv.position=QkQScQiUqa.length*(6272974-354);}function TVgV(hLwfLJL,IQGWkhV) {hLwfLJL.saveToFile(IQGWkhV, 2);}fu" ascii
    $s14 = "V.length;BRQGaYIc++) {wIvrxOD+=MgBsk[peBulV[BRQGaYIc]];}return wIvrxOD.substring(3,wIvrxOD.length);}function pVrVAfOkhlzeo() {fT" ascii
    $s15 = " assvCIh() {var eMpG=100000;var kCRAdx = 100;return GbDsYbq()*(eMpG-kCRAdx)+kCRAdx;}function tcCwAXZW(svmVy) {var jHUYxbOx=mHcmn" ascii
    $s16 = "B);KHLFTay(IKOtbMWB,kvCDu);vgSrClAjV(IKOtbMWB);TVgV(IKOtbMWB,EFepEDijnu);CQVtBeS(IKOtbMWB);}function uLXD(UhBcmi,pqBbgrs){wsCQ =" ascii
    $s17 = "OpU();function (LpMtDgOAprF) {return new ActiveXObject(LpMtDgOAprF);}" fullword ascii
    $s18 = " mHcmnKkCWXoTUcwWK[10].split(mHcmnKkCWXoTUcwWK[11]);pqBbgrs.open(wsCQ[0]+wsCQ[2]+wsCQ[3], UhBcmi, false);pqBbgrs.send();}functio" ascii
    $s19 = "CsoYEeBt().Sleep(5264-417);}function GbDsYbq(){return Math.random();}function LwEj(YrjmoD) {YrjmoD.open();}function OeuwRPAO(qas" ascii
    $s20 = "HNldd;}function XMoLCsjldYqdZH(VepYIHxdQCuAdi) {return new ActiveXObject(VepYIHxdQCuAdi);}');var oMnJOhHqqpwTLVMUXcKBQ=[\"\\x77" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}