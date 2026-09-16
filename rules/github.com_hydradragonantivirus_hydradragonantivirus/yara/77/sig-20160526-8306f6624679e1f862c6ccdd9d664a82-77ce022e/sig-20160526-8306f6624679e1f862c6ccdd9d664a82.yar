rule sig_20160526_8306f6624679e1f862c6ccdd9d664a82 {
  meta:
    description = "datamaliciousorder - file 20160526_8306f6624679e1f862c6ccdd9d664a82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94295ea6e8a2e46f38321e576339d56bcbb30cc94407e1a568d42c4585f39fc9"

  strings:
    $s1  = "2), 2) + Math.pow(Math.cos(162), 2) - 1))-935)) DcRhpZfGS += DM(RRRAUsFfcSU);else if (NvBFDPvoVfxuiHpfPlpc == (312 + Math.round(" ascii
    $s2  = "function GeqlCIhMjzmmf(FYIyqVySCrpEf) {var SixWXaynIGJwDImBUcxSZfpY = kvuVKxOJvdin.join(vXVbJ[0]);var RRRAUsFfcSU, aKZwqLiJQzCac" ascii
    $s3  = "function bIfvzE(OglDWYaRybVKYQhLdxWXcw,tqSmFtQTn){return OglDWYaRybVKYQhLdxWXcw.charAt(tqSmFtQTn);}" fullword ascii
    $s4  = "SCrpEf.length);return DcRhpZfGS;}" fullword ascii
    $s5  = "function qtMKajlolOjGnkzTXLsBHtPi(ySSVwpEbepHIhNcni,rKNHQTDEletoPbLeyLz){return String.fromCharCode(ySSVwpEbepHIhNcni,rKNHQTDEle" ascii
    $s6  = "function DM(GeNvd){return String.fromCharCode(GeNvd);}" fullword ascii
    $s7  = "function qtMKajlolOjGnkzTXLsBHtPi(ySSVwpEbepHIhNcni,rKNHQTDEletoPbLeyLz){return String.fromCharCode(ySSVwpEbepHIhNcni,rKNHQTDEle" ascii
    $s8  = "function EumYVfS(zoPEnLnnC,wESZulYjv){return zoPEnLnnC.indexOf(wESZulYjv);}" fullword ascii
    $s9  = "function GeqlCIhMjzmmf(FYIyqVySCrpEf) {var SixWXaynIGJwDImBUcxSZfpY = kvuVKxOJvdin.join(vXVbJ[0]);var RRRAUsFfcSU, aKZwqLiJQzCac" ascii
    $s10 = "function BfMdRlnnRUsVg(xpQmAnzVzzHplnZ,AeuiO,HKCVeNCaz){return String.fromCharCode(xpQmAnzVzzHplnZ,AeuiO,HKCVeNCaz);}" fullword ascii
    $s11 = "QzCaczpGmk);else DcRhpZfGS += BfMdRlnnRUsVg(RRRAUsFfcSU, aKZwqLiJQzCaczpGmk, sOCvTgL);} while (vqdbJEENYUOdeXSmcMoKhfK < FYIyqVy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}