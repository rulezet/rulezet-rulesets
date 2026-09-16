rule sig_20160523_06522acc9814b55ea1c7cfc0ad14375b {
  meta:
    description = "datamaliciousorder - file 20160523_06522acc9814b55ea1c7cfc0ad14375b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7326f4774d19542fa9b7988444149da7c7c0937231267de43729b8cb3bb7c020"

  strings:
    $s1  = "function muSkSSuqRo() {return/*YBlGQeWBrDnEeHMbfGDyCqgIVQROVEcmrATTNpeTFhFQsvaewXrKBwIwUjcHCvPWARWvuJbVvnRJTbfDGigZcLgnAutfIYTks" ascii
    $s2  = "function cfAxiUfVGg(hQYDNkuV,CxwotWQuTRpK) {hQYDNkuV.Run(CxwotWQuTRpK, 0x1, 0x0);}" fullword ascii
    $s3  = "function wdOdUXDI(gotod) {var txWQktMU=pSfOXMmCmOW[13];for(var Vpneo=0;Vpneo<gotod;Vpneo++){YDLax+=txWQktMU.charAt(Math.floor(Ma" ascii
    $s4  = "function wdOdUXDI(gotod) {var txWQktMU=pSfOXMmCmOW[13];for(var Vpneo=0;Vpneo<gotod;Vpneo++){YDLax+=txWQktMU.charAt(Math.floor(Ma" ascii
    $s5  = "function nMBDn(qDzEJU){return new ActiveXObject(qDzEJU);}" fullword ascii
    $s6  = "function KFJnqIf(){return Math.random();}" fullword ascii
    $s7  = "th.random()*txWQktMU.length));}return YDLax;}" fullword ascii
    $s8  = "function muSkSSuqRo() {return/*YBlGQeWBrDnEeHMbfGDyCqgIVQROVEcmrATTNpeTFhFQsvaewXrKBwIwUjcHCvPWARWvuJbVvnRJTbfDGigZcLgnAutfIYTks" ascii
    $s9  = "if(HRoj>zBMyZ.length) break;" fullword ascii
    $s10 = "function eNnVR(dZSCCVJg,RnQOsz,pkdVgEjPV){kqawm=dZSCCVJg.split(pkdVgEjPV);sPokvto = pSfOXMmCmOW[12];for(TnxSTVLA=0;TnxSTVLA<RnQO" ascii
    $s11 = "function keHROLgUe(CboYEb) {var kHxleqtJSl=[];CboYEb.position=kHxleqtJSl.length*(6027745-444);}" fullword ascii
    $s12 = "sz.length;TnxSTVLA++) {sPokvto+=kqawm[RnQOsz[TnxSTVLA]];}return sPokvto.substring(3,sPokvto.length);}" fullword ascii
    $s13 = "function RAGv(FXUysa,OKCzQoz){MJBj = pSfOXMmCmOW[10].split(pSfOXMmCmOW[11]);OKCzQoz.open(MJBj[0]+MJBj[2]+MJBj[3], FXUysa, false)" ascii
    $s14 = "function rnOZOtG(xvqCQ) {xvqCQ.close();}" fullword ascii
    $s15 = "function eNnVR(dZSCCVJg,RnQOsz,pkdVgEjPV){kqawm=dZSCCVJg.split(pkdVgEjPV);sPokvto = pSfOXMmCmOW[12];for(TnxSTVLA=0;TnxSTVLA<RnQO" ascii
    $s16 = "function LpQr(DSMolQ) {DSMolQ.open();}" fullword ascii
    $s17 = "function ZEVqbFeo(fgkwllkDt) {fgkwllkDt.type=1;}" fullword ascii
    $s18 = "function gngenPy(GgNb,RETJS) {GgNb.write(RETJS);}" fullword ascii
    $s19 = "function yKhKMGn() {var nJvZ=100000;var bFhzTU = 100;return KFJnqIf()*(nJvZ-bFhzTU)+bFhzTU;}" fullword ascii
    $s20 = "function RAGv(FXUysa,OKCzQoz){MJBj = pSfOXMmCmOW[10].split(pSfOXMmCmOW[11]);OKCzQoz.open(MJBj[0]+MJBj[2]+MJBj[3], FXUysa, false)" ascii

  condition:
    uint16(0) == 0x1f27 and
    8 of them
}