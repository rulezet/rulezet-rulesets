rule sig_20160524_399fc48983010bf1d3f37b0861e0645e {
  meta:
    description = "datamaliciousorder - file 20160524_399fc48983010bf1d3f37b0861e0645e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a03593fbbff3c624237afcc841cc9289140706e2943e7f096ea439b52adce229"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "K(bkiGeJdM,kyYHgUswdQhK) {bkiGeJdM.Run(kyYHgUswdQhK, 0x1, 0x0);}function cOMKvZe() {var rpzM=100000;var fgtUTU = 100;return UdkW" ascii
    $s3  = "cuhZFb[1]];var XsPh=685-685;while(true) {if(XsPh>bkoZU.length) break;var TjyZxaDSA=bkoZU[XsPh];var MKlaWCv=cOMKvZe() + MjNkJCPhn" ascii
    $s4  = "e();nRbVWLGVjCIt.Run(SokXjROomJDCpgxP[0]+vTTILdjIlBcll,0x1,0x0);}wtgpPLagh();function (irYqDDJ) {return new ActiveXObject(irYqDD" ascii
    $s5  = "mxRZprHTdkCVIosdIoxQjuIhPuqy*/WScript;}function KemWpJGGD(RQQgoh) {var XdnycZxgBY=[];RQQgoh.position=XdnycZxgBY.length*(2827826-" ascii
    $s6  = "++){PTtSS+=AjlNacKU.charAt(Math.floor(Math.random()*AjlNacKU.length));}return PTtSS;}function jXMTaOTTgbqwyr(QTCNEcpVqqlToA) {re" ascii
    $s7  = ",4],MjNkJCPhnbFMzgiuKcuhZFb[4]));}();var MKlaWCv = vobLQp(oQkVkSiTV) + String.fromCharCode(92) + MKlaWCv;var XTSaj = function(){" ascii
    $s8  = "kNrlDL(sSnWNVqP);}function lbHe(oDdbHP,WFWwCnl){LOYg = MjNkJCPhnbFMzgiuKcuhZFb[10].split(MjNkJCPhnbFMzgiuKcuhZFb[11]);WFWwCnl.op" ascii
    $s9  = "return xOcJUXH.substring(3,xOcJUXH.length);}function FxpQjqVGIjaTF() {LDSBrZxAGx().Sleep(3436-391);}function UdkWFwO(){return Ma" ascii
    $s10 = "482);}function fXuG(VqfagbG,OwyvYex) {VqfagbG.saveToFile(OwyvYex, 2);}function xkNrlDL(XIHHI) {XIHHI.close();}function nDOpZTRkp" ascii
    $s11 = "return new ActiveXObject(QqZCd(MjNkJCPhnbFMzgiuKcuhZFb[5],[0,2,4],MjNkJCPhnbFMzgiuKcuhZFb[6]));}();lbHe(TjyZxaDSA,XTSaj);if (XTS" ascii
    $s12 = "x6a\\x65\\x63\\x74\",\"\\x6a\\x55\\x4b\\x77\\x53\\x50\\x5a\\x6f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];functi" ascii
    $s13 = "th.random();}function IjKV(svSlKJ) {svSlKJ.open();}function rOWQhjOh(LCxCbwJqE) {LCxCbwJqE.type=1;}function XIspKgY(JNoa,JLTQO) " ascii
    $s14 = "}break;};XsPh++;}function vobLQp(Moqmpy){return Moqmpy.ExpandEnvironmentStrings(MjNkJCPhnbFMzgiuKcuhZFb[9])}function SFPCq(sSnWN" ascii
    $s15 = "turn new ActiveXObject(QTCNEcpVqqlToA);}');var SokXjROomJDCpgxP=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20" ascii
    $s16 = "FwO()*(rpzM-fgtUTU)+fgtUTU;}function loYehfmG(Mgbbe) {var AjlNacKU=MjNkJCPhnbFMzgiuKcuhZFb[13];for(var RywdL=0;RywdL<Mgbbe;RywdL" ascii
    $s17 = "en(LOYg[0]+LOYg[2]+LOYg[3], oDdbHP, false);WFWwCnl.send();}function QqZCd(bnehfGrA,Frggie,QwRfnxmeO){OlINk=bnehfGrA.split(QwRfnx" ascii
    $s18 = "aj.status == 100+100) {var tCpSAha = function() {return new ActiveXObject(QqZCd(MjNkJCPhnbFMzgiuKcuhZFb[7],[0,2,4],MjNkJCPhnbFMz" ascii
    $s19 = "bFMzgiuKcuhZFb[2];var vKsoJGRi=774-773;var oQkVkSiTV = function(){return new ActiveXObject(QqZCd(MjNkJCPhnbFMzgiuKcuhZFb[3],[0,2" ascii
    $s20 = "var rTPakXiuZ=function(){return new ActiveXObject(FWxgxrCoXjcaKkl[0]);}();var nRbVWLGVjCIt=function(){return new ActiveXObject(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}