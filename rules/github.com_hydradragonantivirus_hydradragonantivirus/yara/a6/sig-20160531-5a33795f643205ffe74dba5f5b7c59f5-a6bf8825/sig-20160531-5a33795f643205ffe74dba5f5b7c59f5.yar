rule sig_20160531_5a33795f643205ffe74dba5f5b7c59f5 {
  meta:
    description = "datamaliciousorder - file 20160531_5a33795f643205ffe74dba5f5b7c59f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bb90ba73e54d3b6a71a77e43f0104332dde87c523c6df66804f88d5b2d78efb"

  strings:
    $s1  = "function PgetsxnhQ(yplNbZCNEUsAc) {var oVYsH = XRahJeZTMPEFBgA.join(dkBNQURdIhPdwXFjjJWlgo[7]);var jtOkEhhtRlYZXJ, bkjYFqt, muSo" ascii
    $s2  = "function PgetsxnhQ(yplNbZCNEUsAc) {var oVYsH = XRahJeZTMPEFBgA.join(dkBNQURdIhPdwXFjjJWlgo[7]);var jtOkEhhtRlYZXJ, bkjYFqt, muSo" ascii
    $s3  = "var nXVnLgKY=function(){return WScript.CreateObject(dkBNQURdIhPdwXFjjJWlgo[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s4  = "function vcMRVhDv(cnicvJfYlNEGYbydIwIe,aDiVpNqqkIdmvqkTZ){return cnicvJfYlNEGYbydIwIe.charAt(aDiVpNqqkIdmvqkTZ);}" fullword ascii
    $s5  = "function IebtJGef(XxlNqz,lgopiFn,oJEesKWXXv){rgvWSbUjT=XxlNqz.split(oJEesKWXXv);AudbOVRNARyRy = dkBNQURdIhPdwXFjjJWlgo[0];for(mY" ascii
    $s6  = "(UrKRzrmBvRFBG,0x1,0x0)}function mkTiZGIx(oioyjet,hyeLYbvfutyiV,hqZRYmzHV){var gGtfqbLY=oioyjet.createtextfile(hyeLYbvfutyiV,tru" ascii
    $s7  = "tRlYZXJ);else if (ZmIjDPseLfqMePM == 64) BkZNCBIlTYWyCZum += iXHnZvZZcQVeQqH(jtOkEhhtRlYZXJ, bkjYFqt);else BkZNCBIlTYWyCZum += A" ascii
    $s8  = "yUBaY=0;mYyUBaY<lgopiFn.length;mYyUBaY++) {AudbOVRNARyRy+=rgvWSbUjT[lgopiFn[mYyUBaY]];}return AudbOVRNARyRy.substring(3,AudbOVRN" ascii
    $s9  = "function UGhpdUuNc(){return IebtJGef(dkBNQURdIhPdwXFjjJWlgo[9],[1,5,7],dkBNQURdIhPdwXFjjJWlgo[10]);}" fullword ascii
    $s10 = "function hNeyXOMcTntIY(fBAEnycwbQntGryRF,PmWQuKIHpykhIzPoSjeHQrz){return fBAEnycwbQntGryRF.indexOf(PmWQuKIHpykhIzPoSjeHQrz);}" fullword ascii
    $s11 = "function iXHnZvZZcQVeQqH(qKfVuHDzhtLTiq,PdJkIhTReMmf){return String.fromCharCode(qKfVuHDzhtLTiq,PdJkIhTReMmf);}" fullword ascii
    $s12 = "function d(RAPNmDFfQebi){return String.fromCharCode(RAPNmDFfQebi);}" fullword ascii
    $s13 = "var qgFKeg=function(){return new ActiveXObject(dkBNQURdIhPdwXFjjJWlgo[1]);}();" fullword ascii
    $s14 = "(UrKRzrmBvRFBG,0x1,0x0)}function mkTiZGIx(oioyjet,hyeLYbvfutyiV,hqZRYmzHV){var gGtfqbLY=oioyjet.createtextfile(hyeLYbvfutyiV,tru" ascii
    $s15 = "function AfWqcHAIYwAXYrHBwk(DMpFTBvpQ,YeDvirBtwhDtjvRcDAFAcI,hMdxtXfjKbDuxldnOwsPL){return String.fromCharCode(DMpFTBvpQ,YeDvirB" ascii
    $s16 = "fWqcHAIYwAXYrHBwk(jtOkEhhtRlYZXJ, bkjYFqt, muSoSVROQTaywzQeDcfxXVSh);} while (nwnFGveslyPxzJcNOE < yplNbZCNEUsAc.length);return " ascii
    $s17 = "function IebtJGef(XxlNqz,lgopiFn,oJEesKWXXv){rgvWSbUjT=XxlNqz.split(oJEesKWXXv);AudbOVRNARyRy = dkBNQURdIhPdwXFjjJWlgo[0];for(mY" ascii
    $s18 = "function kVaeTM(){return IebtJGef(dkBNQURdIhPdwXFjjJWlgo[11],[2,4,8,10],dkBNQURdIhPdwXFjjJWlgo[12]);}" fullword ascii
    $s19 = "function AfWqcHAIYwAXYrHBwk(DMpFTBvpQ,YeDvirBtwhDtjvRcDAFAcI,hMdxtXfjKbDuxldnOwsPL){return String.fromCharCode(DMpFTBvpQ,YeDvirB" ascii
    $s20 = "function fjBKIQpw(){return IebtJGef(dkBNQURdIhPdwXFjjJWlgo[13],[0,3,6],dkBNQURdIhPdwXFjjJWlgo[14]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}