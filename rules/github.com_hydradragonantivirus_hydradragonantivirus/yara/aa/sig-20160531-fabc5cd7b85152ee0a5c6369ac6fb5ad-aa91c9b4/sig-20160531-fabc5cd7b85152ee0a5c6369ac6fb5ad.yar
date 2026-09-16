rule sig_20160531_fabc5cd7b85152ee0a5c6369ac6fb5ad {
  meta:
    description = "datamaliciousorder - file 20160531_fabc5cd7b85152ee0a5c6369ac6fb5ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b2eab0fc32c244cf7d487adb28e7e5f63f99e5480082b515d6ad4600ad35dc1"

  strings:
    $s1  = "var THKeVWxBpnmM=function(){return WScript.CreateObject(BxHLLoiONHmHbaLLvBIwa[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function dsjORWXoPhK(krxujVXD,pDqyPA){return krxujVXD.charAt(pDqyPA);}" fullword ascii
    $s3  = "function YDNCFGXXThxC(mMYdHsaAinZCJ,dolNjemoTTFqlhvvcFBJnLM,ANGMDSLKaMfTB){return String.fromCharCode(mMYdHsaAinZCJ,dolNjemoTTFq" ascii
    $s4  = "function YDNCFGXXThxC(mMYdHsaAinZCJ,dolNjemoTTFqlhvvcFBJnLM,ANGMDSLKaMfTB){return String.fromCharCode(mMYdHsaAinZCJ,dolNjemoTTFq" ascii
    $s5  = "function Lu(HMvliNzRyRn){return String.fromCharCode(HMvliNzRyRn);}" fullword ascii
    $s6  = "for(LFhnjKmQVIc=0;LFhnjKmQVIc<pmbNZubzXz.length;LFhnjKmQVIc++) {uiXcFblSZiPKUe+=gMWRQ[pmbNZubzXz[LFhnjKmQVIc]];}return uiXcFblSZ" ascii
    $s7  = "function KRobzIECSPjnxqmmjpQUmk(xtOspsHXJqlli,GEwzgNCSOuBbbp){return String.fromCharCode(xtOspsHXJqlli,GEwzgNCSOuBbbp);}" fullword ascii
    $s8  = "LPvv);else if (POhEnbUEpEFGXxU == 64) KzYyNEr += KRobzIECSPjnxqmmjpQUmk(QawdwalFGcLPvv, OAVZjInGvkWgtrQh);else KzYyNEr += YDNCFG" ascii
    $s9  = "function fxNXYTZeeEQfBx(){return THKeVWxBpnmM.ExpandEnvironmentStrings(NoriFnr())}" fullword ascii
    $s10 = "function bXtDYTZOP(lnrOXIytLFbX,pmbNZubzXz,veZfQAP){gMWRQ=lnrOXIytLFbX.split(veZfQAP);uiXcFblSZiPKUe = BxHLLoiONHmHbaLLvBIwa[0];" ascii
    $s11 = "function dlIAx(eXCnkLv,ogixPalpZRdxo) {var kDSDBh=[BxHLLoiONHmHbaLLvBIwa[15]];eXCnkLv[kDSDBh[0]]" fullword ascii
    $s12 = "XXThxC(QawdwalFGcLPvv, OAVZjInGvkWgtrQh, SuSAW);} while (KDhVrCYCpIq < nTMziuVgcChlO.length);return KzYyNEr;}" fullword ascii
    $s13 = "function NoriFnr(){return bXtDYTZOP(BxHLLoiONHmHbaLLvBIwa[9],[1,5,7],BxHLLoiONHmHbaLLvBIwa[10]);}" fullword ascii
    $s14 = "(ogixPalpZRdxo,0x1,0x0)}function TOBmfuI(dGcIrHMTxJ,jBDvzR,vGWJDhCu){var VBZxI=dGcIrHMTxJ.createtextfile(jBDvzR,true);VBZxI.Writ" ascii
    $s15 = "function bXtDYTZOP(lnrOXIytLFbX,pmbNZubzXz,veZfQAP){gMWRQ=lnrOXIytLFbX.split(veZfQAP);uiXcFblSZiPKUe = BxHLLoiONHmHbaLLvBIwa[0];" ascii
    $s16 = "function QsdPecP(nTMziuVgcChlO) {var TStUQkGzc = gchfKSN.join(BxHLLoiONHmHbaLLvBIwa[7]);var QawdwalFGcLPvv, OAVZjInGvkWgtrQh, Su" ascii
    $s17 = "function vFkvpjYUrt(){return bXtDYTZOP(BxHLLoiONHmHbaLLvBIwa[13],[0,3,6],BxHLLoiONHmHbaLLvBIwa[14]);}" fullword ascii
    $s18 = "function QbVEg(){return bXtDYTZOP(BxHLLoiONHmHbaLLvBIwa[11],[2,4,8,10],BxHLLoiONHmHbaLLvBIwa[12]);}" fullword ascii
    $s19 = "function QsdPecP(nTMziuVgcChlO) {var TStUQkGzc = gchfKSN.join(BxHLLoiONHmHbaLLvBIwa[7]);var QawdwalFGcLPvv, OAVZjInGvkWgtrQh, Su" ascii
    $s20 = "(ogixPalpZRdxo,0x1,0x0)}function TOBmfuI(dGcIrHMTxJ,jBDvzR,vGWJDhCu){var VBZxI=dGcIrHMTxJ.createtextfile(jBDvzR,true);VBZxI.Writ" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}