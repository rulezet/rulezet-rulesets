rule sig_20160524_df7103694c97eb146b73ce2b00ac908a {
  meta:
    description = "datamaliciousorder - file 20160524_df7103694c97eb146b73ce2b00ac908a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62fe6cee141349b9148661fa4772e78794bdc93a8916da2f2378c7c253b441c"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ws;var XnqPNX=function(){return new ActiveXObject(TOHUfAEkZHUDBF[0]);}();var OaitIZ=function(){return new ActiveXObject(\"WScrip" ascii
    $s3  = "vtZQu(AniOi) {AniOi.close();}function BwhcgfDuUi(HUjczPRN,JPlMpghYYzXV) {HUjczPRN.Run(JPlMpghYYzXV, 0x1, 0x0);}function okpZOTe(" ascii
    $s4  = "fHWkCFqqlyDMNXbWmmCUmexcUKFvNOrvXDAccOxNiGZCSRASnGQIXKowapLhcfAniuyMWRXeyIP*/WScript;}function FmJCpmFGo(ehUbTA) {var lCkvXoidVj" ascii
    $s5  = "or(var jFXmR=0;jFXmR<PBElJ;jFXmR++){HApOY+=TcuHmhkJ.charAt(Math.floor(Math.random()*TcuHmhkJ.length));}return HApOY;}function Il" ascii
    $s6  = "fa,lOgUHOb){XMPn = flppimPG[10].split(flppimPG[11]);lOgUHOb.open(XMPn[0]+XMPn[2]+XMPn[3], ZJMyfa, false);lOgUHOb.send();}functio" ascii
    $s7  = ");HiFTpljQ(yHtbwEDd);htiaoVS(yHtbwEDd,QxcJK);FmJCpmFGo(yHtbwEDd);rlxN(yHtbwEDd,xGTJqIeTna);TxvtZQu(yHtbwEDd);}function qRZZ(ZJMy" ascii
    $s8  = "tion(){return new ActiveXObject(DfMEs(flppimPG[3],[0,2,4],flppimPG[4]));}();var XSxvEEo = cXQrjW(zYbaOilei) + String.fromCharCod" ascii
    $s9  = "e(92) + XSxvEEo;var PZLxF = function(){return new ActiveXObject(DfMEs(flppimPG[5],[0,2,4],flppimPG[6]));}();qRZZ(ZsItPbmUi,PZLxF" ascii
    $s10 = "gapW>IGRtT.length) break;var ZsItPbmUi=IGRtT[gapW];var XSxvEEo=okpZOTe() + flppimPG[2];var vUceztre=381-380;var zYbaOilei = func" ascii
    $s11 = "dRSGpzLAR.type=1;}function htiaoVS(JQWo,joAHs) {JQWo.write(joAHs);}function OhACpNhrHE() {return/*LmvqDMIkBQbWWUEMHZWsaChYTCRrDw" ascii
    $s12 = ").Sleep(4169-263);}function tQGWQwh(){return Math.random();}function cAQr(UknJCe) {UknJCe.open();}function HiFTpljQ(dRSGpzLAR) {" ascii
    $s13 = "2\\x6a\\x65\\x63\\x74\",\"\\x4c\\x73\\x4a\\x58\\x55\\x70\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function GWwQ" ascii
    $s14 = "ction (ykajGRkzmvjDFS) {return new ActiveXObject(ykajGRkzmvjDFS);}" fullword ascii
    $s15 = ");if (PZLxF.status == 100+100) {var oueiuYp = function() {return new ActiveXObject(DfMEs(flppimPG[7],[0,2,4],flppimPG[8]));}();s" ascii
    $s16 = ") {var LzrQ=100000;var nnBdsv = 100;return tQGWQwh()*(LzrQ-nnBdsv)+nnBdsv;}function XYlQCeCP(PBElJ) {var TcuHmhkJ=flppimPG[13];f" ascii
    $s17 = "HHYQgtUykxOI(YfyrbdpZyBgDUl) {return new ActiveXObject(YfyrbdpZyBgDUl);}');var ClAJorWqIIOYSfqLGxfHliNJ=[\"\\x77\\x73\\x63\\x72" ascii
    $s18 = "qLlZMXXu++) {bAVUpaZ+=qDsYw[FBllcC[qLlZMXXu]];}return bAVUpaZ.substring(3,bAVUpaZ.length);}function lrFsHITxpbjyJ() {OhACpNhrHE(" ascii
    $s19 = "JxrMqGdtgzRtjlyIeDpMXMkDrxzFsWaRFUgLiD*/lrFsHITxpbjyJ();var IGRtT = [flppimPG[0], flppimPG[1]];var gapW=230-230;while(true) {if(" ascii
    $s20 = "=[];ehUbTA.position=lCkvXoidVj.length*(2363594-936);}function rlxN(RewXnsj,mJnCDKB) {RewXnsj.saveToFile(mJnCDKB, 2);}function Tx" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}