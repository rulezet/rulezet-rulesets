rule sig_20160524_11af32fef260b9569aca5aa0aadf19ee {
  meta:
    description = "datamaliciousorder - file 20160524_11af32fef260b9569aca5aa0aadf19ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54dae395a96c1a9173c7c765d59e31c06c211d338241174697061932425e7db7"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "aaTgrIu.Run(FVVumGLAMPDQ, 0x1, 0x0);}function yNhQfSs() {var NQYk=100000;var pFJuQV = 100;return jNrwiiY()*(NQYk-pFJuQV)+pFJuQV;" ascii
    $s3  = "function(){return new ActiveXObject(\"WScript.Shell\");}();var HaKUi = DvaHUDfctsyHAdGn[1]+18827+DvaHUDfctsyHAdGn[2];var GIQPuAF" ascii
    $s4  = "N*/WScript;}function RbqweGctm(HCvvqI) {var zjrLgHVFmu=[];HCvvqI.position=zjrLgHVFmu.length*(1980053-356);}function QGrA(lGsGSYO" ascii
    $s5  = "}function djgLNnEz(QSbkT) {var JQqYXOQM=cBeulahkUsQdOF[13];for(var unhol=0;unhol<QSbkT;unhol++){fohiI+=JQqYXOQM.charAt(Math.floo" ascii
    $s6  = "harCode(92) + aPUtnCP;var zUuCj = function(){return new ActiveXObject(coewH(cBeulahkUsQdOF[5],[0,2,4],cBeulahkUsQdOF[6]));}();Vg" ascii
    $s7  = "ength) break;var uaqhrXgoR=VyDsI[KTwp];var aPUtnCP=yNhQfSs() + cBeulahkUsQdOF[2];var UofrUjIu=523-522;var qDXnHBkQS = function()" ascii
    $s8  = "{return new ActiveXObject(coewH(cBeulahkUsQdOF[3],[0,2,4],cBeulahkUsQdOF[4]));}();var aPUtnCP = jzPMuS(qDXnHBkQS) + String.fromC" ascii
    $s9  = "OGnDEjI.length);}function jcjxTGeKJcwYI() {pnvVHtLTbZ().Sleep(3113-716);}function jNrwiiY(){return Math.random();}function cwDt(" ascii
    $s10 = "\\x25\"];function TuYcml() {var lULLFXUo;var BWYuMnKflG=function(){return new ActiveXObject(DvaHUDfctsyHAdGn[0]);}();var VhEwTxe" ascii
    $s11 = "r(Math.random()*JQqYXOQM.length));}return fohiI;}function ztbhmFWlsAZRpi(xPdiazgFVLveRS) {return new ActiveXObject(xPdiazgFVLveR" ascii
    $s12 = "lRXJiE(osivOEbz);}function VgGP(NpAGhb,PIiAqUv){ywOY = cBeulahkUsQdOF[10].split(cBeulahkUsQdOF[11]);PIiAqUv.open(ywOY[0]+ywOY[2]" ascii
    $s13 = "+ywOY[3], NpAGhb, false);PIiAqUv.send();}function coewH(KPEGjWWZ,rnOkmY,alzOWAjWv){ntZgs=KPEGjWWZ.split(alzOWAjWv);OGnDEjI = cBe" ascii
    $s14 = "GP(uaqhrXgoR,zUuCj);if (zUuCj.status == 100+100) {var pfroUwT = function() {return new ActiveXObject(coewH(cBeulahkUsQdOF[7],[0," ascii
    $s15 = "Iw,2,true);lULLFXUo.Write('var cBeulahkUsQdOF=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x69\\x72\\x63\\x6f\\x6e\\x64\\x69\\x7" ascii
    $s16 = "ytwHVO) {ytwHVO.open();}function MvdbXMjY(bmYVxYILk) {bmYVxYILk.type=1;}function DWNKfcR(YjKp,xUgbf) {YjKp.write(xUgbf);}functio" ascii
    $s17 = "xlrmycbEuKS[0]+GIQPuAFIw,0x1,0x0);}TuYcml();function (KACrzsC) {return new ActiveXObject(KACrzsC);}" fullword ascii
    $s18 = "ulahkUsQdOF[12];for(cVfPqODV=0;cVfPqODV<rnOkmY.length;cVfPqODV++) {OGnDEjI+=ntZgs[rnOkmY[cVfPqODV]];}return OGnDEjI.substring(3," ascii
    $s19 = "nHrkIdNasIikEl*/jcjxTGeKJcwYI();var VyDsI = [cBeulahkUsQdOF[0], cBeulahkUsQdOF[1]];var KTwp=202-202;while(true) {if(KTwp>VyDsI.l" ascii
    $s20 = "atch(e) {}break;};KTwp++;}function jzPMuS(XwmKIg){return XwmKIg.ExpandEnvironmentStrings(cBeulahkUsQdOF[9])}function fPFMQ(osivO" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}