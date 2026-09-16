rule sig_20160527_92a8bfabb283de042c18bed4e5869fd4 {
  meta:
    description = "datamaliciousorder - file 20160527_92a8bfabb283de042c18bed4e5869fd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c279298857d10b3cd5307dc6d51994eb37001bc17c79311575fbc575dce6f3ea"

  strings:
    $s1  = "function owDIYDJSzKpE() {return WScript;}function xEpIPrm(){return Bwxvb.ExpandEnvironmentStrings(CmUhvcT())}" fullword ascii
    $s2  = "function aEQCcbTxucdaL(imtcVFHlUTGbNivB,aSpCiiXZFQFpbeSlFQlKPgZ){return imtcVFHlUTGbNivB.charAt(aSpCiiXZFQFpbeSlFQlKPgZ);}" fullword ascii
    $s3  = "function OF(YTgcnLpfhrMgRunmp){return String.fromCharCode(YTgcnLpfhrMgRunmp);}" fullword ascii
    $s4  = "function OPQrOfclfcdBIpaNQnjHNWgw(yBQGS,hNTniopocxDvAkBsOMqMZyZd){return String.fromCharCode(yBQGS,hNTniopocxDvAkBsOMqMZyZd);}" fullword ascii
    $s5  = "(ifyXRuiMhSdt == 64) gKWyJnTymRUX += OF(kBaJwokNUGUMwXfwdG);else if (vsVZE == 64) gKWyJnTymRUX += OPQrOfclfcdBIpaNQnjHNWgw(kBaJw" ascii
    $s6  = "function gtxMwJKxDkYMePPnIjaiv(MlETdwmlKbYzNtrs,ElkQlKBtxOfA,EutDmwW){return String.fromCharCode(MlETdwmlKbYzNtrs,ElkQlKBtxOfA,E" ascii
    $s7  = "var OythGfvDqf = yAEwqSi.createtextfile(Bwxvb.ExpandEnvironmentStrings(NRWanTpv[2]+NRWanTpv[3])+String.fromCharCode(92)+NRWanTpv" ascii
    $s8  = "hUzNNU=0;VthhUzNNU<vjyZrzWDqX.length;VthhUzNNU++) {ecVBfuKzF+=HMgkCEY[vjyZrzWDqX[VthhUzNNU]];}return ecVBfuKzF.substring(3,ecVBf" ascii
    $s9  = "function bDhxg(){return qjuxucY(NRWanTpv[10],[2,4,8,10],NRWanTpv[11]);}" fullword ascii
    $s10 = "function qWoAFEwE(JhsSZazeTAANSzciup,wuViqxJGmfq){return JhsSZazeTAANSzciup.indexOf(wuViqxJGmfq);}" fullword ascii
    $s11 = "okNUGUMwXfwdG, JbYCmPdteCOgUISis);else gKWyJnTymRUX += gtxMwJKxDkYMePPnIjaiv(kBaJwokNUGUMwXfwdG, JbYCmPdteCOgUISis, KtQBNuEDXhYe" ascii
    $s12 = "push(\"K\");JlspUSzeQb.push(\"L\");JlspUSzeQb.push(\"a\");JlspUSzeQb.push(\"b\");JlspUSzeQb.push(\"c\");JlspUSzeQb.push(\"P\");J" ascii
    $s13 = "function qjuxucY(yFsHlZgVvjUSl,vjyZrzWDqX,OnyvwwPMFGP){HMgkCEY=yFsHlZgVvjUSl.split(OnyvwwPMFGP);ecVBfuKzF = NRWanTpv[14];for(Vth" ascii
    $s14 = "WaL);} while (DVhzeVyhvyYvkrF < doCKwpLcjWmLQ.length);return gKWyJnTymRUX;}" fullword ascii
    $s15 = "function MhXqvURjNd(doCKwpLcjWmLQ) {var ObdgsYUnDyd = JlspUSzeQb.join(NRWanTpv[6]);var kBaJwokNUGUMwXfwdG, JbYCmPdteCOgUISis, Kt" ascii
    $s16 = "function CmUhvcT(){return qjuxucY(NRWanTpv[8],[1,5,7],NRWanTpv[9]);}" fullword ascii
    $s17 = "var Bwxvb=function(){return owDIYDJSzKpE().CreateObject(NRWanTpv[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s18 = "function MhXqvURjNd(doCKwpLcjWmLQ) {var ObdgsYUnDyd = JlspUSzeQb.join(NRWanTpv[6]);var kBaJwokNUGUMwXfwdG, JbYCmPdteCOgUISis, Kt" ascii
    $s19 = "function qjuxucY(yFsHlZgVvjUSl,vjyZrzWDqX,OnyvwwPMFGP){HMgkCEY=yFsHlZgVvjUSl.split(OnyvwwPMFGP);ecVBfuKzF = NRWanTpv[14];for(Vth" ascii
    $s20 = "function SGMLyuzJ(EoBkwOkQJ,ixumIQr) {var CLleZHxRVmy=[NRWanTpv[15]];EoBkwOkQJ[CLleZHxRVmy[0]](ixumIQr,0x1,0x0)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}