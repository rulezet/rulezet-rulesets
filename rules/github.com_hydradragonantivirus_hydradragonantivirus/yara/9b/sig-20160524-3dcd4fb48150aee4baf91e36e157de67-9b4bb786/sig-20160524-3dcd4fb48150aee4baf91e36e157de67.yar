rule sig_20160524_3dcd4fb48150aee4baf91e36e157de67 {
  meta:
    description = "datamaliciousorder - file 20160524_3dcd4fb48150aee4baf91e36e157de67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca3e59a1575e35f14bc87b4942a0ed51c9e372d23604a6ddf3f10d7588f2727"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "PVurZC.saveToFile(TxPeNqK, 2);}function GpPJNkm(jFIzi) {jFIzi.close();}function LwUhlKobKl(arnjUayq,qBwRfSMxFyAv) {arnjUayq.Run(" ascii
    $s3  = "yy(GmtFbTAQR) + String.fromCharCode(92) + bjNwjIp;var vlpJQ = function(){return new ActiveXObject(TZYEz(AAAzhXToj[5],[0,2,4],AAA" ascii
    $s4  = "r HdTE=388-388;while(true) {if(HdTE>oMnUc.length) break;var EAbxzlnyM=oMnUc[HdTE];var bjNwjIp=uxHKjpu() + AAAzhXToj[2];var iscDb" ascii
    $s5  = "bltlBKy.length));}return OnnrY;}function idaWSsIdxdfpdv(hDngitiuYJsYWY) {return new ActiveXObject(hDngitiuYJsYWY);}');var ZZKrzi" ascii
    $s6  = "cDW.open();}function xshVmTIa(wpwKgTrXW) {wpwKgTrXW.type=1;}function pJlVPrA(KeHm,suwwz) {KeHm.write(suwwz);}function HqpvEUlJnh" ascii
    $s7  = "th);}function meCvKcqvnMtSi() {HqpvEUlJnh().Sleep(3190-837);}function udHxDhI(){return Math.random();}function qYnL(dfzcDW) {dfz" ascii
    $s8  = "function wdAkwsyde(JNjHTt) {var iPoNdPLUBq=[];JNjHTt.position=iPoNdPLUBq.length*(2683474-504);}function EnFF(IPVurZC,TxPeNqK) {I" ascii
    $s9  = "zhXToj[6]));}();ZcQd(EAbxzlnyM,vlpJQ);if (vlpJQ.status == 100+100) {var GLGJUib = function() {return new ActiveXObject(TZYEz(AAA" ascii
    $s10 = "65\\x6d\\x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x44\\x76\\x70\\x53\\x64\\x59\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25" ascii
    $s11 = "tUPJnLWHAesOpRd[3])+String.fromCharCode(92)+ADOzOw;OeAWYkFt = bLfzIjo.OpenTextFile(DXvpCuQlreNXV,2,true);OeAWYkFt.Write('var AAA" ascii
    $s12 = "0x0);}NNzuz();function (gVhfwFJWDg) {return new ActiveXObject(gVhfwFJWDg);}" fullword ascii
    $s13 = "YkFt;var bLfzIjo=function(){return new ActiveXObject(WtUPJnLWHAesOpRd[0]);}();var pflwIl=function(){return new ActiveXObject(\"W" ascii
    $s14 = "QiA=349-348;var GmtFbTAQR = function(){return new ActiveXObject(TZYEz(AAAzhXToj[3],[0,2,4],AAAzhXToj[4]));}();var bjNwjIp = RTxP" ascii
    $s15 = "12];for(jmTSZEeq=0;jmTSZEeq<rcjhWs.length;jmTSZEeq++) {jqvitCA+=PiFjH[rcjhWs[jmTSZEeq]];}return jqvitCA.substring(3,jqvitCA.leng" ascii
    $s16 = ");GpPJNkm(DrNwTLbP);}function ZcQd(CAIiUG,YgomKEt){IsEw = AAAzhXToj[10].split(AAAzhXToj[11]);YgomKEt.open(IsEw[0]+IsEw[2]+IsEw[3" ascii
    $s17 = "jIp);} catch(e) {}break;};HdTE++;}function RTxPyy(flbcjN){return flbcjN.ExpandEnvironmentStrings(AAAzhXToj[9])}function VZHkc(Dr" ascii
    $s18 = "], CAIiUG, false);YgomKEt.send();}function TZYEz(RxrwttKo,rcjhWs,LEUFOMvJr){PiFjH=RxrwttKo.split(LEUFOMvJr);jqvitCA = AAAzhXToj[" ascii
    $s19 = "qBwRfSMxFyAv, 0x1, 0x0);}function uxHKjpu() {var Jmbb=100000;var YitTca = 100;return udHxDhI()*(Jmbb-YitTca)+YitTca;}function CN" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}