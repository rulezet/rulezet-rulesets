rule sig_20160523_650e0c8a7bbb26da30f12e9b1a5caef2 {
  meta:
    description = "datamaliciousorder - file 20160523_650e0c8a7bbb26da30f12e9b1a5caef2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5082888a116e014312197e17b88ceb3e9e9606bf400ad8c78fde1dd568c6e024"

  strings:
    $s1  = "function MuWUNcGSeH(GYKZLXJJ,nbwXIFEFaNWO) {GYKZLXJJ.Run(nbwXIFEFaNWO, 0x1, 0x0);}" fullword ascii
    $s2  = "function NmwMlLrSox() {return/*TxAwuUrFgNtmbiORwvANbEqVYNFVPlLDEgZIrDezSSIoltwZhVksUigkUnVpSmLcYKjAfzLGgzQqNKByJsCpIzCiixKtlbvSn" ascii
    $s3  = "function zNquaDrx(WRYqh) {var oTVfuSEz=eTbqUEzh[13];for(var sJyWu=0;sJyWu<WRYqh;sJyWu++){QBUAC+=oTVfuSEz.charAt(Math.floor(Math." ascii
    $s4  = "function zNquaDrx(WRYqh) {var oTVfuSEz=eTbqUEzh[13];for(var sJyWu=0;sJyWu<WRYqh;sJyWu++){QBUAC+=oTVfuSEz.charAt(Math.floor(Math." ascii
    $s5  = "function Prjn(AQSVzf) {AQSVzf.open();}" fullword ascii
    $s6  = "function PcXaNAxO(MzJpHTjEb) {MzJpHTjEb.type=1;}" fullword ascii
    $s7  = "function NmwMlLrSox() {return/*TxAwuUrFgNtmbiORwvANbEqVYNFVPlLDEgZIrDezSSIoltwZhVksUigkUnVpSmLcYKjAfzLGgzQqNKByJsCpIzCiixKtlbvSn" ascii
    $s8  = "function yaaUcrhvC(HEuHFa) {var cktbUlhgap=[];HEuHFa.position=cktbUlhgap.length*(9667261-652);}" fullword ascii
    $s9  = "function OCubfJX(qDKpl) {qDKpl.close();}" fullword ascii
    $s10 = "function fhgTfLp(Oxwh,HXQGX) {Oxwh.write(HXQGX);}" fullword ascii
    $s11 = "if(XCGp>dFrwc.length) break;" fullword ascii
    $s12 = "function VmBjo(wtINYljL,TGRPKy,BfdTPbBsU){WtQNS=wtINYljL.split(BfdTPbBsU);QBkKvWJ = eTbqUEzh[12];for(TAqZxUBq=0;TAqZxUBq<TGRPKy." ascii
    $s13 = "function ybIEM(bSczCM){return new ActiveXObject(bSczCM);}" fullword ascii
    $s14 = "function MjBiOg(bSczCM){return bSczCM.ExpandEnvironmentStrings(eTbqUEzh[9])}" fullword ascii
    $s15 = "length;TAqZxUBq++) {QBkKvWJ+=WtQNS[TGRPKy[TAqZxUBq]];}return QBkKvWJ.substring(3,QBkKvWJ.length);}" fullword ascii
    $s16 = "function fvkcm(ckuipzWN,IOwCy,PkudhSgdxI){Prjn(ckuipzWN);PcXaNAxO(ckuipzWN);fhgTfLp(ckuipzWN,IOwCy);yaaUcrhvC(ckuipzWN);NlvB(cku" ascii
    $s17 = "function fvkcm(ckuipzWN,IOwCy,PkudhSgdxI){Prjn(ckuipzWN);PcXaNAxO(ckuipzWN);fhgTfLp(ckuipzWN,IOwCy);yaaUcrhvC(ckuipzWN);NlvB(cku" ascii
    $s18 = "random()*oTVfuSEz.length));}return QBUAC;}" fullword ascii
    $s19 = "function yxzG(lxmqJp,oLnuQoG){lOdX = eTbqUEzh[10].split(eTbqUEzh[11]);oLnuQoG.open(lOdX[0]+lOdX[2]+lOdX[3], lxmqJp, false);oLnuQ" ascii
    $s20 = "function VmBjo(wtINYljL,TGRPKy,BfdTPbBsU){WtQNS=wtINYljL.split(BfdTPbBsU);QBkKvWJ = eTbqUEzh[12];for(TAqZxUBq=0;TAqZxUBq<TGRPKy." ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}