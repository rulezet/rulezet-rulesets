rule sig_20160526_4bf4f38f56c5687b41c77cbd0a97c7ca {
  meta:
    description = "datamaliciousorder - file 20160526_4bf4f38f56c5687b41c77cbd0a97c7ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4ed51a36439feb6d7079cb06c11f4d2f54a07e4f796d21c26a27207c65a29fb"

  strings:
    $s1  = "4 + Math.round((Math.pow(Math.sin(153), 2) + Math.pow(Math.cos(153), 2) - 1))-510)) ClsHi += JP(ZRFSzSFW);else if (tTmKZGOgqzdgB" ascii
    $s2  = "function pkaBB(iHcsPihmToSJT) {var fBxvhZGTYhN = rFsIuEPFQQqwn.join(aRgbmxGOUyv[0]);var ZRFSzSFW, qSGrghlnsWQCLujPwkuIEXzN, EHoY" ascii
    $s3  = "function tRdwFdZJPqH(iqdbxiwK,vOCnZEvVjMiKulIBZePwIa){return iqdbxiwK.charAt(vOCnZEvVjMiKulIBZePwIa);}" fullword ascii
    $s4  = "CcnFCZlcnnEf < iHcsPihmToSJT.length);return ClsHi;}" fullword ascii
    $s5  = "function HpvzyuyOuIajXAMcyfC(kHDMLyDHDDivAwsxCXVzqQT,SFIgQdYSqIewL,QPZyamBJREuOrxAiJDEcbc){return String.fromCharCode(kHDMLyDHDD" ascii
    $s6  = "function YFFUMvZrXSLcDnXSy(gUZncuSgfeawb,tGUCHykz){return String.fromCharCode(gUZncuSgfeawb,tGUCHykz);}" fullword ascii
    $s7  = "function HpvzyuyOuIajXAMcyfC(kHDMLyDHDDivAwsxCXVzqQT,SFIgQdYSqIewL,QPZyamBJREuOrxAiJDEcbc){return String.fromCharCode(kHDMLyDHDD" ascii
    $s8  = "function oanhwhNO(YrGHQmq,KfpwZqjNy){return YrGHQmq.indexOf(KfpwZqjNy);}" fullword ascii
    $s9  = ", qSGrghlnsWQCLujPwkuIEXzN);else ClsHi += HpvzyuyOuIajXAMcyfC(ZRFSzSFW, qSGrghlnsWQCLujPwkuIEXzN, EHoYGAfoHWSTPhP);} while (LCRs" ascii
    $s10 = "function pkaBB(iHcsPihmToSJT) {var fBxvhZGTYhN = rFsIuEPFQQqwn.join(aRgbmxGOUyv[0]);var ZRFSzSFW, qSGrghlnsWQCLujPwkuIEXzN, EHoY" ascii
    $s11 = "function JP(qIgjZpHWcDJwy){return String.fromCharCode(qIgjZpHWcDJwy);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}