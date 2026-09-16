rule sig_20160524_a5d10931711a1537a3537a4e162ec72b {
  meta:
    description = "datamaliciousorder - file 20160524_a5d10931711a1537a3537a4e162ec72b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17033cac1b68befea51459141bc8e30a38a0e468d5c4084711cb784115d531c8"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "c.Run(qKFKAxnAslmD, 0x1, 0x0);}function NWVKEET() {var fRro=100000;var JxLRPU = 100;return TIkvxlE()*(fRro-JxLRPU)+JxLRPU;}funct" ascii
    $s3  = "= mvlkWq(vEoqhBXod) + String.fromCharCode(92) + GCWiGzZ;var DfchV = function(){return new ActiveXObject(AbMRj(Ruffiddxc[5],[0,2," ascii
    $s4  = "1]];var JuQq=827-827;while(true) {if(JuQq>CSmkG.length) break;var KphCiTALz=CSmkG[JuQq];var GCWiGzZ=NWVKEET() + Ruffiddxc[2];var" ascii
    $s5  = "Mp) {ziBwMsr.saveToFile(FnoSAMp, 2);}function Amxmpsd(yJaQP) {yJaQP.close();}function FMwEEIgJCu(FvYZeHRc,qKFKAxnAslmD) {FvYZeHR" ascii
    $s6  = "iddxc[12];for(HDgXjQTS=0;HDgXjQTS<fjvSgX.length;HDgXjQTS++) {NYxghnq+=KRvvK[fjvSgX[HDgXjQTS]];}return NYxghnq.substring(3,NYxghn" ascii
    $s7  = "DHqu[3], BAtvmL, false);TLHzjBq.send();}function AbMRj(ucRDTGEH,fjvSgX,ikDGkhBxr){KRvvK=ucRDTGEH.split(ikDGkhBxr);NYxghnq = Ruff" ascii
    $s8  = "gs(wmJwcmyrhXD[3])+String.fromCharCode(92)+PpXzxgloctkiR;mnEDVZWZhVK = mEjDaOVoFaPK.OpenTextFile(xVnVxhiatDenSQ,2,true);mnEDVZWZ" ascii
    $s9  = "ript;}function SNIEGopMs(cnphnv) {var lFHeZQvgDt=[];cnphnv.position=lFHeZQvgDt.length*(7706021-446);}function oSvu(ziBwMsr,FnoSA" ascii
    $s10 = ") {GCLYTm.open();}function fIHrKZkJ(zClFWwXXa) {zClFWwXXa.type=1;}function leeiaTQ(tvbA,gzMat) {tvbA.write(gzMat);}function eRCy" ascii
    $s11 = "LoqxTV);Amxmpsd(QvQFgVNG);}function wIQH(BAtvmL,TLHzjBq){DHqu = Ruffiddxc[10].split(Ruffiddxc[11]);TLHzjBq.open(DHqu[0]+DHqu[2]+" ascii
    $s12 = "DVZWZhVK;var mEjDaOVoFaPK=function(){return new ActiveXObject(wmJwcmyrhXD[0]);}();var rSeSAwO=function(){return new ActiveXObjec" ascii
    $s13 = "4],Ruffiddxc[6]));}();wIQH(KphCiTALz,DfchV);if (DfchV.status == 100+100) {var xdvmqOn = function() {return new ActiveXObject(AbM" ascii
    $s14 = "x63\\x74\",\"\\x7a\\x48\\x55\\x58\\x49\\x64\\x68\\x4b\\x51\\x45\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];functi" ascii
    $s15 = " hyaoVntF=234-233;var vEoqhBXod = function(){return new ActiveXObject(AbMRj(Ruffiddxc[3],[0,2,4],Ruffiddxc[4]));}();var GCWiGzZ " ascii
    $s16 = "om()*JQavujkn.length));}return bbZNJ;}function CDPUJPgtzNwXyC(WyDMsmnxWhAmsz) {return new ActiveXObject(WyDMsmnxWhAmsz);}');var " ascii
    $s17 = ",0x0);}TthVkbFEfwLSw();function (KtsdqbybiLSlNC) {return new ActiveXObject(KtsdqbybiLSlNC);}" fullword ascii
    $s18 = "q.length);}function YtfNpAbSPpYoC() {eRCywJGqFD().Sleep(4787-413);}function TIkvxlE(){return Math.random();}function lUeP(GCLYTm" ascii
    $s19 = "d,GCWiGzZ);} catch(e) {}break;};JuQq++;}function mvlkWq(pmuvBS){return pmuvBS.ExpandEnvironmentStrings(Ruffiddxc[9])}function Fs" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}