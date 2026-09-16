rule sig_20151211_254fc290eebe4ea7fa77f6cab112dced {
  meta:
    description = "datamaliciousorder - file 20151211_254fc290eebe4ea7fa77f6cab112dced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "177e9e57d490f26d8e9987e768da39484e1f5c26edbcdd3932382e0811855938"

  strings:
    $s1  = "function cXFjfJKhYQZ(LStYgEtN,cYGzyk){return LStYgEtN.split(cYGzyk)}" fullword ascii
    $s2  = "function ojSFVWo(SAEUkxKbtxRFrmYTPUIfiuWlsDgUxoAFQyFI) {return !isNaN(parseFloat(SAEUkxKbtxRFrmYTPUIfiuWlsDgUxoAFQyFI)) && isFin" ascii
    $s3  = "function ojSFVWo(SAEUkxKbtxRFrmYTPUIfiuWlsDgUxoAFQyFI) {return !isNaN(parseFloat(SAEUkxKbtxRFrmYTPUIfiuWlsDgUxoAFQyFI)) && isFin" ascii
    $s4  = "function uwRglUniSnpwMSAOVExTqSByZYmnuhZTSzOwRQEMckxihzNmIFxrPe(pSCdGESggzzma,gnBjjQfedNGzEv){ return IfzDG[yuewd(pSCdGESggzzma[" ascii
    $s5  = "var i=new Array(\"26\",\"2a\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"37\",\"" ascii
    $s6  = "function yuewd(RCkPmGipJoW,uyDlXjPJZLUHh,zXJpGgSf){CxsF=parseInt(RCkPmGipJoW,uyDlXjPJZLUHh);xNfTH=CxsF.toString(zXJpGgSf);return" ascii
    $s7  = "function yuewd(RCkPmGipJoW,uyDlXjPJZLUHh,zXJpGgSf){CxsF=parseInt(RCkPmGipJoW,uyDlXjPJZLUHh);xNfTH=CxsF.toString(zXJpGgSf);return" ascii
    $s8  = "var C=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = " xNfTH;}function MifsqfIUAxozkuw(sKQjmfuRQLfVQGQPO){eval(sKQjmfuRQLfVQGQPO)}" fullword ascii
    $s10 = "function uwRglUniSnpwMSAOVExTqSByZYmnuhZTSzOwRQEMckxihzNmIFxrPe(pSCdGESggzzma,gnBjjQfedNGzEv){ return IfzDG[yuewd(pSCdGESggzzma[" ascii
    $s11 = "var i=new Array(\"26\",\"2a\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"37\",\"" ascii
    $s12 = "fxLylZQoW[oNTcuoxHvNQ]=(-730+730)/993; while(true) { if(fxLylZQoW[oNTcuoxHvNQ] > icLSq[oNTcuoxHvNQ].length-(-563+978)/415) { bre" ascii
    $s13 = "var C=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function llmjaofmzBKdiLEzJ(icLSq){utaTWrlYPwK= '';oNTcuoxHvNQ=(-309+309)/402; while(true){if(oNTcuoxHvNQ >= (-639+741)/51)break;" ascii
    $s15 = "Q]++;}oNTcuoxHvNQ++;} return utaTWrlYPwK}" fullword ascii
    $s16 = "function llmjaofmzBKdiLEzJ(icLSq){utaTWrlYPwK= '';oNTcuoxHvNQ=(-309+309)/402; while(true){if(oNTcuoxHvNQ >= (-639+741)/51)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}