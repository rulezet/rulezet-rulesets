rule sig_20160523_57a5ae3ad3e4ab3468ed0d70d083c581 {
  meta:
    description = "datamaliciousorder - file 20160523_57a5ae3ad3e4ab3468ed0d70d083c581.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "210f501a09c9b5690a32b56be6ffaf1665741fd923094198035ad089ea0b5350"

  strings:
    $s1  = "function nWNVqPdSIA(YaQjLlKu,ZQPlbHeoDdbH) {YaQjLlKu.Run(ZQPlbHeoDdbH, 0x1, 0x0);}" fullword ascii
    $s2  = "function bpVBVITI(pjYsO) {var BAdyYsOW=rnsMvhOYKiXWdvCQ[2];for(var kRXox=0;kRXox<pjYsO;kRXox++){QEfwG+=BAdyYsOW.charAt(Math.floo" ascii
    $s3  = "function bpVBVITI(pjYsO) {var BAdyYsOW=rnsMvhOYKiXWdvCQ[2];for(var kRXox=0;kRXox<pjYsO;kRXox++){QEfwG+=BAdyYsOW.charAt(Math.floo" ascii
    $s4  = "<aDSAMK.length;JGRioQkV++) {RYUsrqp+=kSiTV[aDSAMK[JGRioQkV]];}return RYUsrqp.substring(3,RYUsrqp.length);}" fullword ascii
    $s5  = "function LnVSo(ghOTjyZx,aDSAMK,laWCvvKso){kSiTV=ghOTjyZx.split(laWCvvKso);RYUsrqp = rnsMvhOYKiXWdvCQ[13];for(JGRioQkV=0;JGRioQkV" ascii
    $s6  = "function LnVSo(ghOTjyZx,aDSAMK,laWCvvKso){kSiTV=ghOTjyZx.split(laWCvvKso);RYUsrqp = rnsMvhOYKiXWdvCQ[13];for(JGRioQkV=0;JGRioQkV" ascii
    $s7  = "function XTSajtC(){return Math.random();}" fullword ascii
    $s8  = "function pSAh(aoLNsr) {aoLNsr.open();}" fullword ascii
    $s9  = "Mg, false);bbeAjlN.send();}" fullword ascii
    $s10 = "function loYe(hfmGMg,bbeAjlN){acKU = rnsMvhOYKiXWdvCQ[11].split(rnsMvhOYKiXWdvCQ[12]);bbeAjlN.open(acKU[0]+acKU[2]+acKU[3], hfmG" ascii
    $s11 = "if (ACFfgym==0) break;" fullword ascii
    $s12 = "function DapGPm(jsMayl){return jsMayl.ExpandEnvironmentStrings(rnsMvhOYKiXWdvCQ[10])}" fullword ascii
    $s13 = "function YImM(oqmpyvo,bLQpDNT) {oqmpyvo.saveToFile(bLQpDNT, 2);}" fullword ascii
    $s14 = "function loYe(hfmGMg,bbeAjlN){acKU = rnsMvhOYKiXWdvCQ[11].split(rnsMvhOYKiXWdvCQ[12]);bbeAjlN.open(acKU[0]+acKU[2]+acKU[3], hfmG" ascii
    $s15 = "function hrslNfQ(lbcP,ccthJ) {lbcP.write(ccthJ);}" fullword ascii
    $s16 = "function PYQvLSF(PCqsS) {PCqsS.close();}" fullword ascii
    $s17 = "function UjsRNZs() {var OrVF=100000;var xEDSlZ = 100;return XTSajtC()*(OrVF-xEDSlZ)+xEDSlZ;}" fullword ascii
    $s18 = "function wPOvs(DbkoZUcO,MKvZe,rpzMfgtUTU){pSAh(DbkoZUcO);aXdsQSri(DbkoZUcO);hrslNfQ(DbkoZUcO,MKvZe);wQkFnEPOf(DbkoZUcO);YImM(Dbk" ascii
    $s19 = "function nRqYM(jsMayl){return new ActiveXObject(jsMayl);}" fullword ascii
    $s20 = "r(Math.random()*BAdyYsOW.length));}return QEfwG;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}