rule sig_20160526_ea6732877e1edc41c7759fe478a93c0e {
  meta:
    description = "datamaliciousorder - file 20160526_ea6732877e1edc41c7759fe478a93c0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eca6fb7cfd42c6bec1bcf83e76491a53415e197ac2d01e0d2e43992de9ffb43"

  strings:
    $s1  = "function ITTEPQa(JQYaNKsaLjKKL) {var tuaSFXJDcQ = xNeuSAFxpDQjfMcYRdISDt.join(NzZFcyMnuXbXIiDdddEEsU[0]);var XVQawmDwRPBfUfDKBTf" ascii
    $s2  = "function sMrphKNsexCpzFZWNSoh(pESKwZEgDAdAwT,kTBmnfwtVyYsNB){return pESKwZEgDAdAwT.charAt(kTBmnfwtVyYsNB);}" fullword ascii
    $s3  = "BxKMKk(XVQawmDwRPBfUfDKBTf, zVhgKAkVdEVTekdVm);else VkGnMoL += zUjeeeZiOdAdqCNoR(XVQawmDwRPBfUfDKBTf, zVhgKAkVdEVTekdVm, DrKTmuJ" ascii
    $s4  = "fsQqTmy);} while (zOxbnkZqBLirB < JQYaNKsaLjKKL.length);return VkGnMoL;}" fullword ascii
    $s5  = "function zUjeeeZiOdAdqCNoR(ywZQVzJeIPtVGboCtZMzQ,IjsHlsIXNmCgtFhn,UwQKbp){return String.fromCharCode(ywZQVzJeIPtVGboCtZMzQ,IjsHl" ascii
    $s6  = "function HXZLCXBIxBvRwbRjYcLFf(YPatEGvEMsMkroHZhVCKpaJA,lljYwAEfInsGsJ){return YPatEGvEMsMkroHZhVCKpaJA.indexOf(lljYwAEfInsGsJ);" ascii
    $s7  = "function ITTEPQa(JQYaNKsaLjKKL) {var tuaSFXJDcQ = xNeuSAFxpDQjfMcYRdISDt.join(NzZFcyMnuXbXIiDdddEEsU[0]);var XVQawmDwRPBfUfDKBTf" ascii
    $s8  = "function dFyTfaCfABxKMKk(zmKFdIyJEpAuBEfQxsta,fPuGhmk){return String.fromCharCode(zmKFdIyJEpAuBEfQxsta,fPuGhmk);}" fullword ascii
    $s9  = "function JY(vrSsKJJOeiaGIbGmNkWGt){return String.fromCharCode(vrSsKJJOeiaGIbGmNkWGt);}" fullword ascii
    $s10 = "function zUjeeeZiOdAdqCNoR(ywZQVzJeIPtVGboCtZMzQ,IjsHlsIXNmCgtFhn,UwQKbp){return String.fromCharCode(ywZQVzJeIPtVGboCtZMzQ,IjsHl" ascii
    $s11 = "function HXZLCXBIxBvRwbRjYcLFf(YPatEGvEMsMkroHZhVCKpaJA,lljYwAEfInsGsJ){return YPatEGvEMsMkroHZhVCKpaJA.indexOf(lljYwAEfInsGsJ);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}