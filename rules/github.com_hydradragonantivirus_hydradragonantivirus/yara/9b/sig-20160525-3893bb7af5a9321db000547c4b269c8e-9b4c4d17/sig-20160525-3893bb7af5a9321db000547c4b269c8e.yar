rule sig_20160525_3893bb7af5a9321db000547c4b269c8e {
  meta:
    description = "datamaliciousorder - file 20160525_3893bb7af5a9321db000547c4b269c8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29a3169051e2a1c457d7fdee05b8f175208c47c308ca98f00c5b18278e5f904e"

  strings:
    $s1  = "Math.cos(788), 2) - 1))-484)) FhqGjcWbhSe += VSdPtdpGJLIt(MTUtSdIQSZmK, hnkRSaDOSgK);else FhqGjcWbhSe += uLZyFjydplQgthNvJZNv(MT" ascii
    $s2  = "function cfPADvrnoT(ZTbjkQZGQDvGB) {var SHOnNjETMVDoWs = PQbEpKw.join(iiZCemQwlporVlDxhKtsIR[0]);var MTUtSdIQSZmK, hnkRSaDOSgK, " ascii
    $s3  = ")-335)) FhqGjcWbhSe += Yl(MTUtSdIQSZmK);else if (OylOAqrJAfTIbNHfJT == (548 + Math.round((Math.pow(Math.sin(788), 2) + Math.pow(" ascii
    $s4  = "function tDoZTf(EYfwVtClkDRQCWjcDyc,PvrpNLtXvfh){return EYfwVtClkDRQCWjcDyc.charAt(PvrpNLtXvfh);}" fullword ascii
    $s5  = "function uLZyFjydplQgthNvJZNv(xLhZTJgcFejtKatOsnix,hAQBzUbRyHdtjgG,QAWCyRNqsROqgMhMsXrUiIG){return String.fromCharCode(xLhZTJgcF" ascii
    $s6  = "function uLZyFjydplQgthNvJZNv(xLhZTJgcFejtKatOsnix,hAQBzUbRyHdtjgG,QAWCyRNqsROqgMhMsXrUiIG){return String.fromCharCode(xLhZTJgcF" ascii
    $s7  = "function Yl(auZHcCgYOqothwupnBLUQUBd){return String.fromCharCode(auZHcCgYOqothwupnBLUQUBd);}" fullword ascii
    $s8  = "function cfPADvrnoT(ZTbjkQZGQDvGB) {var SHOnNjETMVDoWs = PQbEpKw.join(iiZCemQwlporVlDxhKtsIR[0]);var MTUtSdIQSZmK, hnkRSaDOSgK, " ascii
    $s9  = "function VSdPtdpGJLIt(StuMhLZPsjwpsqwoIMsOQE,trCmzsCMxWHBgSJh){return String.fromCharCode(StuMhLZPsjwpsqwoIMsOQE,trCmzsCMxWHBgSJ" ascii
    $s10 = "UtSdIQSZmK, hnkRSaDOSgK, cvQGzlJHJtNwkppUNe);} while (HOxOidBMhLZWb < ZTbjkQZGQDvGB.length);return FhqGjcWbhSe;}" fullword ascii
    $s11 = "function VSdPtdpGJLIt(StuMhLZPsjwpsqwoIMsOQE,trCmzsCMxWHBgSJh){return String.fromCharCode(StuMhLZPsjwpsqwoIMsOQE,trCmzsCMxWHBgSJ" ascii
    $s12 = "function qLRHjicLiX(LVCMlSNIJxSqrwJlAJQDcond,pThOpQ){return LVCMlSNIJxSqrwJlAJQDcond.indexOf(pThOpQ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}