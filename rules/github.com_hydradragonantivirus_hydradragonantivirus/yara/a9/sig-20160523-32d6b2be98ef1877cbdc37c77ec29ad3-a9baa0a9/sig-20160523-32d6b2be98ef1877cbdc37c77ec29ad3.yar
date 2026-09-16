rule sig_20160523_32d6b2be98ef1877cbdc37c77ec29ad3 {
  meta:
    description = "datamaliciousorder - file 20160523_32d6b2be98ef1877cbdc37c77ec29ad3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96c425af9042f75d1693f45706cd292686ddee29722536800b52d1c206270bb5"

  strings:
    $s1  = "function MhHQsOwvcq() {return/*DIGfEWtrUuuzwSEsPTcYzRqYgGhDwEcRNwysTIUjRmCKOneMqaXBtrVApPfTTBxReWMtIESDFpadlFimJOnfFCYFROoQFWzcK" ascii
    $s2  = "function XcFHiSLuZT(mqvmCcyt,zxVXLPRffzAi) {mqvmCcyt.Run(zxVXLPRffzAi, 0x1, 0x0);}" fullword ascii
    $s3  = "function fEqlPGHs(xtSzi) {var DbZzjaCo=nnaegnGKfcnbd[13];for(var uKSTG=0;uKSTG<xtSzi;uKSTG++){PYUOF+=DbZzjaCo.charAt(Math.floor(" ascii
    $s4  = "function fEqlPGHs(xtSzi) {var DbZzjaCo=nnaegnGKfcnbd[13];for(var uKSTG=0;uKSTG<xtSzi;uKSTG++){PYUOF+=DbZzjaCo.charAt(Math.floor(" ascii
    $s5  = "Math.random()*DbZzjaCo.length));}return PYUOF;}" fullword ascii
    $s6  = "UVnL.length;CLXAdjEz++) {jjavRle+=ZBlOi[kWUVnL[CLXAdjEz]];}return jjavRle.substring(3,jjavRle.length);}" fullword ascii
    $s7  = "function BVddd(vbNGPIar,kWUVnL,jNlOoNuxu){ZBlOi=vbNGPIar.split(jNlOoNuxu);jjavRle = nnaegnGKfcnbd[12];for(CLXAdjEz=0;CLXAdjEz<kW" ascii
    $s8  = "function mKbHp(tNsuIlDX,MiakQ,EokRUWDQZQ){GDIC(tNsuIlDX);VqBbrMKs(tNsuIlDX);HjwXEFO(tNsuIlDX,MiakQ);tvtNZWeuu(tNsuIlDX);HEfo(tNs" ascii
    $s9  = "function fHUBNwD(xhTgV) {xhTgV.close();}" fullword ascii
    $s10 = "function ZPTjPlYVxpVPY() {MhHQsOwvcq().Sleep(2432845-321);}" fullword ascii
    $s11 = "function VqBbrMKs(wQVKTXfIQ) {wQVKTXfIQ.type=1;}" fullword ascii
    $s12 = "function GDIC(PUlmXH) {PUlmXH.open();}" fullword ascii
    $s13 = "function tKVV(nVhMOz,yRyegCu){wqrG = nnaegnGKfcnbd[10].split(nnaegnGKfcnbd[11]);yRyegCu.open(wqrG[0]+wqrG[2]+wqrG[3], nVhMOz, fa" ascii
    $s14 = "function bzmnYCm() {var AuaU=100000;var TThLxH = 100;return WVkPCrw()*(AuaU-TThLxH)+TThLxH;}" fullword ascii
    $s15 = "function VDCyqP(DnlBGd){return DnlBGd.ExpandEnvironmentStrings(nnaegnGKfcnbd[9])}" fullword ascii
    $s16 = "function MhHQsOwvcq() {return/*DIGfEWtrUuuzwSEsPTcYzRqYgGhDwEcRNwysTIUjRmCKOneMqaXBtrVApPfTTBxReWMtIESDFpadlFimJOnfFCYFROoQFWzcK" ascii
    $s17 = "function tvtNZWeuu(DsaEXQ) {var CJRxpgRYKW=[];DsaEXQ.position=CJRxpgRYKW.length*(1375798-343);}" fullword ascii
    $s18 = "function WVkPCrw(){return Math.random();}" fullword ascii
    $s19 = "function HEfo(IVkrlYh,YcfYQHU) {IVkrlYh.saveToFile(YcfYQHU, 2);}" fullword ascii
    $s20 = "function tKVV(nVhMOz,yRyegCu){wqrG = nnaegnGKfcnbd[10].split(nnaegnGKfcnbd[11]);yRyegCu.open(wqrG[0]+wqrG[2]+wqrG[3], nVhMOz, fa" ascii

  condition:
    uint16(0) == 0x1f27 and
    8 of them
}