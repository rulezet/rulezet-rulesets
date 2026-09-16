rule sig_20160531_012410ab1f8a845efb0dbe7bf9a71ddf {
  meta:
    description = "datamaliciousorder - file 20160531_012410ab1f8a845efb0dbe7bf9a71ddf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44ff66fa8e78373fecfb0c03af02323a8f3ac5622cd6593814753d6c665a5c5e"

  strings:
    $s1  = "var bZVqHIc=function(){return WScript.CreateObject(PJTEKPseQIExzNpoSUEBm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function VBJYbjrkTlQ(pctXLnrTcDRRsk,ALkQTPhIkCGyOvPQqM){return pctXLnrTcDRRsk.charAt(ALkQTPhIkCGyOvPQqM);}" fullword ascii
    $s3  = "function livCUVLcIcs(){return InwilhgAn(PJTEKPseQIExzNpoSUEBm[11],[2,4,8,10],PJTEKPseQIExzNpoSUEBm[12]);}" fullword ascii
    $s4  = "xqxoi = rPKieFLk>> 8 & 0xff;BSeSvVYqjawa = rPKieFLk & 0xff;if (mvdvMmb == 64) JVqZuwQuaoYMGpAF += lT(RMCFmQMrxiog);else if (gDkO" ascii
    $s5  = "(pZhVLBoGcoRGV,0x1,0x0)}function onsfMRZ(hbbcsAxasc,YtzEdR,aotHBjWjTNOHH){var gwRJOEpm=hbbcsAxasc.createtextfile(YtzEdR,true);gw" ascii
    $s6  = "function lT(qCUzPFWeNiYCDnqfrmb){return String.fromCharCode(qCUzPFWeNiYCDnqfrmb);}" fullword ascii
    $s7  = "duJhjx=0;kQGTduJhjx<yHMezAvuk.length;kQGTduJhjx++) {EoSkSJVS+=PiiPmFEIrm[yHMezAvuk[kQGTduJhjx]];}return EoSkSJVS.substring(3,EoS" ascii
    $s8  = "function IjLlej(RKYNyAS,pZhVLBoGcoRGV) {var sIVeCkgZaoEtsb=[PJTEKPseQIExzNpoSUEBm[15]];RKYNyAS[sIVeCkgZaoEtsb[0]]" fullword ascii
    $s9  = "(pZhVLBoGcoRGV,0x1,0x0)}function onsfMRZ(hbbcsAxasc,YtzEdR,aotHBjWjTNOHH){var gwRJOEpm=hbbcsAxasc.createtextfile(YtzEdR,true);gw" ascii
    $s10 = "function InwilhgAn(sCkaF,yHMezAvuk,VoZKFBkwtYj){PiiPmFEIrm=sCkaF.split(VoZKFBkwtYj);EoSkSJVS = PJTEKPseQIExzNpoSUEBm[0];for(kQGT" ascii
    $s11 = "function VajOCC(){return InwilhgAn(PJTEKPseQIExzNpoSUEBm[13],[0,3,6],PJTEKPseQIExzNpoSUEBm[14]);}" fullword ascii
    $s12 = "function jdBPyKtgRPLHxOVGVoiezCBn(QfVUJfZGWDcEqB,xNXmFMNuwLWdsunzz){return QfVUJfZGWDcEqB.indexOf(xNXmFMNuwLWdsunzz);}" fullword ascii
    $s13 = "var joBCg=function(){return new ActiveXObject(PJTEKPseQIExzNpoSUEBm[1]);}();" fullword ascii
    $s14 = "function lubEgzhBEWXq(){return InwilhgAn(PJTEKPseQIExzNpoSUEBm[9],[1,5,7],PJTEKPseQIExzNpoSUEBm[10]);}" fullword ascii
    $s15 = "function wPRKPFX(LdtwyRdCuEu,RTtlsgkNdyCEeXpZaBUiR){return String.fromCharCode(LdtwyRdCuEu,RTtlsgkNdyCEeXpZaBUiR);}" fullword ascii
    $s16 = "function WlmEUX(){return bZVqHIc.ExpandEnvironmentStrings(lubEgzhBEWXq())}" fullword ascii
    $s17 = "function FQYgLIPW(BzUJHAvkcvpoG) {var YOFakcbxypI = bvbJzfdzRYQGgAkZVc.join(PJTEKPseQIExzNpoSUEBm[7]);var RMCFmQMrxiog, FzcqqzKv" ascii
    $s18 = "function InwilhgAn(sCkaF,yHMezAvuk,VoZKFBkwtYj){PiiPmFEIrm=sCkaF.split(VoZKFBkwtYj);EoSkSJVS = PJTEKPseQIExzNpoSUEBm[0];for(kQGT" ascii
    $s19 = "IsqTx(RMCFmQMrxiog, FzcqqzKvfORZfxegxqxoi, BSeSvVYqjawa);} while (nZBRYecs < BzUJHAvkcvpoG.length);return JVqZuwQuaoYMGpAF;}" fullword ascii
    $s20 = "push(\"D\");bvbJzfdzRYQGgAkZVc.push(\"3\");bvbJzfdzRYQGgAkZVc.push(\"E\");bvbJzfdzRYQGgAkZVc.push(\"F\");bvbJzfdzRYQGgAkZVc.push" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}