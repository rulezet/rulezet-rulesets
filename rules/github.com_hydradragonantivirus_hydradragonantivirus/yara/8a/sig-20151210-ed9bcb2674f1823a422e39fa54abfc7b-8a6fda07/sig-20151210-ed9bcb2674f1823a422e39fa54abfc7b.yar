rule sig_20151210_ed9bcb2674f1823a422e39fa54abfc7b {
  meta:
    description = "datamaliciousorder - file 20151210_ed9bcb2674f1823a422e39fa54abfc7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2534f0e76941239c783888c9511ca3ee5a4fc6c9ab64fa33f5ce9ea484be6663"

  strings:
    $s1  = "function VFClUES(QHdJfUFNvAVvNUgBqJMusMezZBDNpanHPuBT) {return !isNaN(parseFloat(QHdJfUFNvAVvNUgBqJMusMezZBDNpanHPuBT)) && isFin" ascii
    $s2  = "function VFClUES(QHdJfUFNvAVvNUgBqJMusMezZBDNpanHPuBT) {return !isNaN(parseFloat(QHdJfUFNvAVvNUgBqJMusMezZBDNpanHPuBT)) && isFin" ascii
    $s3  = ";}} return kaakfquUyBh}" fullword ascii
    $s4  = " qcfGE;}function fMXHwqwobohaBAc(ymWSFaRomebIBBLvd){eval(ymWSFaRomebIBBLvd)}" fullword ascii
    $s5  = "function DUrtuxOWavOdmSlKP(gnALl){kaakfquUyBh= '';for(RKrGUacjQmR=(-271+271)/900; RKrGUacjQmR < (805+293)/549; RKrGUacjQmR++) {a" ascii
    $s6  = "function QAoFFcVASwoAHCEwrtwIAxWugrxHPhGZwtOdrgBpAXMwrgoUIteYxH(hUQrYVDTqjNaJ,sWWEDbDOUiXvKw){ return qMaESXfnrfZmR[PjeiN(hUQrYV" ascii
    $s7  = "tyEKILJp[RKrGUacjQmR]=(-958+958)/894; while(true) { if(atyEKILJp[RKrGUacjQmR] > gnALl[RKrGUacjQmR].length-(60+807)/867) { break;" ascii
    $s8  = "function PjeiN(JEGfQaJZZWT,XvJzheEIDMJBo,oXjzTqhb){mriK=parseInt(JEGfQaJZZWT,XvJzheEIDMJBo);qcfGE=mriK.toString(oXjzTqhb);return" ascii
    $s9  = "bpeYDzM=(-640+640)/703;while(true){if(bpeYDzM>=(119731+845)/942){break;}qMaESXfnrfZmR[bpeYDzM]=String.fromCharCode(bpeYDzM);bpeY" ascii
    $s10 = "function QAoFFcVASwoAHCEwrtwIAxWugrxHPhGZwtOdrgBpAXMwrgoUIteYxH(hUQrYVDTqjNaJ,sWWEDbDOUiXvKw){ return qMaESXfnrfZmR[PjeiN(hUQrYV" ascii
    $s11 = "function DUrtuxOWavOdmSlKP(gnALl){kaakfquUyBh= '';for(RKrGUacjQmR=(-271+271)/900; RKrGUacjQmR < (805+293)/549; RKrGUacjQmR++) {a" ascii
    $s12 = "function PjeiN(JEGfQaJZZWT,XvJzheEIDMJBo,oXjzTqhb){mriK=parseInt(JEGfQaJZZWT,XvJzheEIDMJBo);qcfGE=mriK.toString(oXjzTqhb);return" ascii
    $s13 = "bpeYDzM=(-640+640)/703;while(true){if(bpeYDzM>=(119731+845)/942){break;}qMaESXfnrfZmR[bpeYDzM]=String.fromCharCode(bpeYDzM);bpeY" ascii
    $s14 = "function IAFnnaUoDvc(xVrhAaKt,EduooG){return xVrhAaKt.split(EduooG)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}