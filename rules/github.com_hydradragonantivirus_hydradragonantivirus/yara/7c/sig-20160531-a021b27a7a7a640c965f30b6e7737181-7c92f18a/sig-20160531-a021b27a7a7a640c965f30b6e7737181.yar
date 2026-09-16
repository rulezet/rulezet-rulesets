rule sig_20160531_a021b27a7a7a640c965f30b6e7737181 {
  meta:
    description = "datamaliciousorder - file 20160531_a021b27a7a7a640c965f30b6e7737181.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bbfecc409ee80974afc4b07e4333bccc1b6c830497968d0a36183f8a0ba71e4"

  strings:
    $s1  = "function UYuPwz(EbnsVHpG,RuNzsiLZFsavGzxCcrAewt){return EbnsVHpG.charAt(RuNzsiLZFsavGzxCcrAewt);}" fullword ascii
    $s2  = "var BZmbsvoASUaasb=function(){return WScript.CreateObject(nJTfQawbgBJroWTK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "function ozOEAzpO(GTuETVIBKXwgg) {var DZjYToflB = DUXKDrXShZGFDUGyDQL.join(nJTfQawbgBJroWTK[7]);var BjQvkqyeyyvKS, wCPyNmtmWXu, " ascii
    $s4  = "eyyvKS);else if (TxcSbwXAWnzVgiGxgMnqUH == 64) zvLWHQEFkRgETJoBXKRPgzmQ += rHACsefMgDi(BjQvkqyeyyvKS, wCPyNmtmWXu);else zvLWHQEF" ascii
    $s5  = "kRgETJoBXKRPgzmQ += nIArEbBbiTlwZYkKhF(BjQvkqyeyyvKS, wCPyNmtmWXu, ETpkJuRFnblIKQ);} while (KWKIooSF < GTuETVIBKXwgg.length);ret" ascii
    $s6  = "function kLxYJMkGDtL(){return ToPFUmmZCu(nJTfQawbgBJroWTK[13],[0,3,6],nJTfQawbgBJroWTK[14]);}" fullword ascii
    $s7  = "function IlmnK(TxNVDZZUPUu,OztluLsaS) {var hNarhV=[nJTfQawbgBJroWTK[15]];TxNVDZZUPUu[hNarhV[0]]" fullword ascii
    $s8  = "(OztluLsaS,0x1,0x0)}function RiVkeDr(BcGzhNIVZfv,ISgNbwoeje,MOeSz){var aYLSl=BcGzhNIVZfv.createtextfile(ISgNbwoeje,true);aYLSl.W" ascii
    $s9  = "function ToPFUmmZCu(lCQIXzP,UCOgUhfvcl,aDAnGmu){YdqgvWjSrUrsE=lCQIXzP.split(aDAnGmu);KTlxqnMnit = nJTfQawbgBJroWTK[0];for(kloCuh" ascii
    $s10 = "function XnvwLHtAuho(){return ToPFUmmZCu(nJTfQawbgBJroWTK[9],[1,5,7],nJTfQawbgBJroWTK[10]);}" fullword ascii
    $s11 = "function ozOEAzpO(GTuETVIBKXwgg) {var DZjYToflB = DUXKDrXShZGFDUGyDQL.join(nJTfQawbgBJroWTK[7]);var BjQvkqyeyyvKS, wCPyNmtmWXu, " ascii
    $s12 = "function ToPFUmmZCu(lCQIXzP,UCOgUhfvcl,aDAnGmu){YdqgvWjSrUrsE=lCQIXzP.split(aDAnGmu);KTlxqnMnit = nJTfQawbgBJroWTK[0];for(kloCuh" ascii
    $s13 = "var cIYpMIXHe=function(){return new ActiveXObject(nJTfQawbgBJroWTK[1]);}();" fullword ascii
    $s14 = "(OztluLsaS,0x1,0x0)}function RiVkeDr(BcGzhNIVZfv,ISgNbwoeje,MOeSz){var aYLSl=BcGzhNIVZfv.createtextfile(ISgNbwoeje,true);aYLSl.W" ascii
    $s15 = "function puJBeSYX(){return BZmbsvoASUaasb.ExpandEnvironmentStrings(XnvwLHtAuho())}" fullword ascii
    $s16 = "function nIArEbBbiTlwZYkKhF(UzSuCtmgUijLFHNojzuzWL,sqvFwpzMiynsTJSMbvVkyu,NbrBfSDNu){return String.fromCharCode(UzSuCtmgUijLFHNo" ascii
    $s17 = "function nIArEbBbiTlwZYkKhF(UzSuCtmgUijLFHNojzuzWL,sqvFwpzMiynsTJSMbvVkyu,NbrBfSDNu){return String.fromCharCode(UzSuCtmgUijLFHNo" ascii
    $s18 = "MJbCy=0;kloCuhMJbCy<UCOgUhfvcl.length;kloCuhMJbCy++) {KTlxqnMnit+=YdqgvWjSrUrsE[UCOgUhfvcl[kloCuhMJbCy]];}return KTlxqnMnit.subs" ascii
    $s19 = "function cMbMmQmeeNMtR(){return ToPFUmmZCu(nJTfQawbgBJroWTK[11],[2,4,8,10],nJTfQawbgBJroWTK[12]);}" fullword ascii
    $s20 = "function WC(XIEhqZskseMbbMNwNEPpeT){return String.fromCharCode(XIEhqZskseMbbMNwNEPpeT);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}