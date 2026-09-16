rule sig_20160524_b0a04dd9ab6bf5d6792b6427ee4c7d56 {
  meta:
    description = "datamaliciousorder - file 20160524_b0a04dd9ab6bf5d6792b6427ee4c7d56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c8bfb6d7df2ba9caf4ed7a2d4a1878ffd44de4cc0303befd2c742ce68cb8713"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "=function(){return new ActiveXObject(AgmwrjdI[0]);}();var ThauMoQSo=function(){return new ActiveXObject(\"WScript.Shell\");}();v" ascii
    $s3  = "zWL, 2);}function OZLIkLv(yXqJA) {yXqJA.close();}function xSPELWxckH(TOSEOdjR,tPgZupiidvmW) {TOSEOdjR.Run(tPgZupiidvmW, 0x1, 0x0" ascii
    $s4  = "tion(){return new ActiveXObject(zDbfV(PUKzWHgWeO[3],[0,2,4],PUKzWHgWeO[4]));}();var LXcswhD = pTGtHW(mDFOXGwDd) + String.fromCha" ascii
    $s5  = "rCode(92) + LXcswhD;var SbUVv = function(){return new ActiveXObject(zDbfV(PUKzWHgWeO[5],[0,2,4],PUKzWHgWeO[6]));}();aSPz(lAUDSFf" ascii
    $s6  = "pW>aLrxD.length) break;var lAUDSFfAD=aLrxD[HhpW];var LXcswhD=sTdlhkU() + PUKzWHgWeO[2];var IQWTyAar=361-360;var mDFOXGwDd = func" ascii
    $s7  = "JnrtXpYYEKwVrQipvzhKCdRnWtlBpNNGTevhsIIhZtynzCqDcaiIugyGOMkeTiSeWotoIwmKowvZzHslCVdZhDYtzyeZrXR*/WScript;}function BqIagMTfB(taq" ascii
    $s8  = "\\x79\\x6d\\x73\\x61\\x77\\x4e\\x62\\x4a\\x57\\x5a\\x45\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function LKIXH" ascii
    $s9  = "function (FduQIiWlojF) {return new ActiveXObject(FduQIiWlojF);}" fullword ascii
    $s10 = "rWv) {var hIGWAejVVL=[];taqrWv.position=hIGWAejVVL.length*(5855787-582);}function Pjqg(lgjuIBz,iQOKzWL) {lgjuIBz.saveToFile(iQOK" ascii
    $s11 = "HhpW++;}function pTGtHW(jGtwMI){return jGtwMI.ExpandEnvironmentStrings(PUKzWHgWeO[9])}function ExkdJ(jKqcksBP,LZJBz,XlrKfhPdOV){" ascii
    $s12 = "urn tgOPG;}function beagHVZXipWwCS(BXpIarrrfViWbC) {return new ActiveXObject(BXpIarrrfViWbC);}');var adVoIuWnoNFxcbmFQWW=[\"\\x7" ascii
    $s13 = "bRjuxCr(tWJJMeaBX) {tWJJMeaBX.type=1;}function ZLNYmBJ(nWJi,PISCd) {nWJi.write(PISCd);}function eyTuIsZhDt() {return/*enYtftFLBC" ascii
    $s14 = "tion aSPz(DLCsEW,RxGjcoP){JYPK = PUKzWHgWeO[10].split(PUKzWHgWeO[11]);RxGjcoP.open(JYPK[0]+JYPK[2]+JYPK[3], DLCsEW, false);RxGjc" ascii
    $s15 = "sLsfO;LQYim = ZjhTLBg.OpenTextFile(UARdrPrJNoOo,2,true);LQYim.Write('var PUKzWHgWeO=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73" ascii
    $s16 = "uLjNHtvBdRTlFLmkLfMovFfQgoBIRMOh*/WTTkORCJHwSle();var aLrxD = [PUKzWHgWeO[0], PUKzWHgWeO[1]];var HhpW=639-639;while(true) {if(Hh" ascii
    $s17 = ");}function sTdlhkU() {var OcYG=100000;var GDlAEG = 100;return bGJJXoN()*(OcYG-GDlAEG)+GDlAEG;}function EmZLhdLP(zIesK) {var pWs" ascii
    $s18 = "AD,SbUVv);if (SbUVv.status == 100+100) {var xljBgEz = function() {return new ActiveXObject(zDbfV(PUKzWHgWeO[7],[0,2,4],PUKzWHgWe" ascii
    $s19 = "HwSle() {eyTuIsZhDt().Sleep(5350-807);}function bGJJXoN(){return Math.random();}function NRyB(wBhEts) {wBhEts.open();}function P" ascii
    $s20 = "oP.send();}function zDbfV(iBrOmNuC,UXhkJP,UjMBByITt){vVndH=iBrOmNuC.split(UjMBByITt);iljBLTL = PUKzWHgWeO[12];for(CAcntUOC=0;CAc" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}