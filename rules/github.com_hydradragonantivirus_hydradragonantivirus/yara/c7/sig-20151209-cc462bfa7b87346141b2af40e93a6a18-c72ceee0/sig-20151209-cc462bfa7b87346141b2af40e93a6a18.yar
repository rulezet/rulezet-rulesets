rule sig_20151209_cc462bfa7b87346141b2af40e93a6a18 {
  meta:
    description = "datamaliciousorder - file 20151209_cc462bfa7b87346141b2af40e93a6a18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62fbbaa96cfdb635b4c7c89bb0cb2fc82a82b2a9bd4d835f5cb93299871bb443"

  strings:
    $s1  = "function vHpyeIT(PahgHYqdSywilJXwjpiWlHDZmdFGsDsOgasg) {return !isNaN(parseFloat(PahgHYqdSywilJXwjpiWlHDZmdFGsDsOgasg)) && isFin" ascii
    $s2  = "function vHpyeIT(PahgHYqdSywilJXwjpiWlHDZmdFGsDsOgasg) {return !isNaN(parseFloat(PahgHYqdSywilJXwjpiWlHDZmdFGsDsOgasg)) && isFin" ascii
    $s3  = "function eXfWG(KkcLSjIDJnh,fNSUnbVeSfvxb,ucGwGoVB){hgHC=parseInt(KkcLSjIDJnh,fNSUnbVeSfvxb);BSxgU=hgHC.toString(ucGwGoVB);return" ascii
    $s4  = "function UtHRJSVoCFnkmMNsN(NTelG){bhIaBopNibT= '';for(fOnKKrgYTGi=(-970+970)/809; fOnKKrgYTGi < (1258+250)/754; fOnKKrgYTGi++) {" ascii
    $s5  = " BSxgU;}function kQWPuDzgFqdiofd(DrkiqCLQRwwkHciQH){eval(DrkiqCLQRwwkHciQH)}" fullword ascii
    $s6  = "VARnTaDrD[fOnKKrgYTGi]=(-754+754)/887; while(true) { if(VARnTaDrD[fOnKKrgYTGi] > NTelG[fOnKKrgYTGi].length-(-328+473)/145) { bre" ascii
    $s7  = "}} return bhIaBopNibT}" fullword ascii
    $s8  = "function mDMQwkttSlN(WhYHGdcM,XojTWW){return WhYHGdcM.split(XojTWW)}" fullword ascii
    $s9  = "function eXfWG(KkcLSjIDJnh,fNSUnbVeSfvxb,ucGwGoVB){hgHC=parseInt(KkcLSjIDJnh,fNSUnbVeSfvxb);BSxgU=hgHC.toString(ucGwGoVB);return" ascii
    $s10 = "function OpKkmqtBpPsTHfUCAABLFRVrBStsRnIwSLSeaeWQxWJcrMlaVXmNFb(AhORZHuxSaxxF,vtNWESomJPNlgk){ return bSOfe[eXfWG(AhORZHuxSaxxF[" ascii
    $s11 = "function OpKkmqtBpPsTHfUCAABLFRVrBStsRnIwSLSeaeWQxWJcrMlaVXmNFb(AhORZHuxSaxxF,vtNWESomJPNlgk){ return bSOfe[eXfWG(AhORZHuxSaxxF[" ascii
    $s12 = "function UtHRJSVoCFnkmMNsN(NTelG){bhIaBopNibT= '';for(fOnKKrgYTGi=(-970+970)/809; fOnKKrgYTGi < (1258+250)/754; fOnKKrgYTGi++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}