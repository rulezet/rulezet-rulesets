rule sig_20160526_faa9cef541067f3ff26647d551882c77 {
  meta:
    description = "datamaliciousorder - file 20160526_faa9cef541067f3ff26647d551882c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e2cbe21e6ac4efeefc0f30fffe33b7d3c35c8f3fc7fe0ef3c5680202e1b027"

  strings:
    $s1  = "function MpLHyZIZXzmc(vcbGXDcbJsgpG) {var vgNWGKtPdmeDCMPbe = YMhbsXtZirciYEwwpfsfZ.join(SHPYcZhmkpq[0]);var lBtOvhiND, xCnmKV, " ascii
    $s2  = "pow(Math.cos(244), 2) - 1))-584) & 0xff;EdLwzjReoOOVfLCVs = LTdOSEajv & 0xff;if (eYaIBpFTVC == (874 + Math.round((Math.pow(Math." ascii
    $s3  = "41), 2) + Math.pow(Math.cos(41), 2) - 1))-999) & 0xff;xCnmKV = LTdOSEajv>> (592 + Math.round((Math.pow(Math.sin(244), 2) + Math." ascii
    $s4  = "sin(89), 2) + Math.pow(Math.cos(89), 2) - 1))-810)) SjlJRfkI += g(lBtOvhiND);else if (dikYyL == (181 + Math.round((Math.pow(Math" ascii
    $s5  = ".sin(808), 2) + Math.pow(Math.cos(808), 2) - 1))-117)) SjlJRfkI += KYXENidnDv(lBtOvhiND, xCnmKV);else SjlJRfkI += TPeFpvnhyadWSo" ascii
    $s6  = "function wyaLumqzOwGKE(UiZwKUFZqtTwttUMVYur,WEuFZswKWFSw){return UiZwKUFZqtTwttUMVYur.charAt(WEuFZswKWFSw);}" fullword ascii
    $s7  = "function MpLHyZIZXzmc(vcbGXDcbJsgpG) {var vgNWGKtPdmeDCMPbe = YMhbsXtZirciYEwwpfsfZ.join(SHPYcZhmkpq[0]);var lBtOvhiND, xCnmKV, " ascii
    $s8  = "function g(vBIBzPbcThqXNC){return String.fromCharCode(vBIBzPbcThqXNC);}" fullword ascii
    $s9  = "function TPeFpvnhyadWSonnQaVu(WIjHazaJgSnTJW,IYZQvsdYol,SKFVGfCMPCPAALL){return String.fromCharCode(WIjHazaJgSnTJW,IYZQvsdYol,SK" ascii
    $s10 = "function YovRXaLGbHrudlU(TINIXFcfewWOblLcCXZPtw,CyHaLtcfeTeySPgNWOGauK){return TINIXFcfewWOblLcCXZPtw.indexOf(CyHaLtcfeTeySPgNWO" ascii
    $s11 = "nnQaVu(lBtOvhiND, xCnmKV, EdLwzjReoOOVfLCVs);} while (oJiafX < vcbGXDcbJsgpG.length);return SjlJRfkI;}" fullword ascii
    $s12 = "function YovRXaLGbHrudlU(TINIXFcfewWOblLcCXZPtw,CyHaLtcfeTeySPgNWOGauK){return TINIXFcfewWOblLcCXZPtw.indexOf(CyHaLtcfeTeySPgNWO" ascii
    $s13 = "function KYXENidnDv(PNlFsuwfIhXVIRARehKz,dZZJpL){return String.fromCharCode(PNlFsuwfIhXVIRARehKz,dZZJpL);}" fullword ascii
    $s14 = "function TPeFpvnhyadWSonnQaVu(WIjHazaJgSnTJW,IYZQvsdYol,SKFVGfCMPCPAALL){return String.fromCharCode(WIjHazaJgSnTJW,IYZQvsdYol,SK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}