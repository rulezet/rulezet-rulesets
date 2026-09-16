rule sig_20160525_27d33f6bb5b79db93f8561e472f8ccca {
  meta:
    description = "datamaliciousorder - file 20160525_27d33f6bb5b79db93f8561e472f8ccca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db456f0b0e59c6c4614a13744ff626bff4e8ae6f865e7baeb5f871a46be85372"

  strings:
    $s1  = "h.pow(Math.sin(447), 2) + Math.pow(Math.cos(447), 2) - 1))-10)) QPYmzcyKkUSd += iz(BUDKTtlBpQZVea);else if (iXvDmsjCJtvLEdhiRxAi" ascii
    $s2  = "), 2) - 1))-561) & 0xff;nFWthNvCWOgVTLIdfeqsVXMb = tFygPhgDzMGNMzheBkSwC>> (761 + Math.round((Math.pow(Math.sin(294), 2) + Math." ascii
    $s3  = "function wHYhsPGlC(uNcBZabxihcrI) {var gUBJIbejVDbyurmmUfj = JkDwMJMDSA.join(NAZbT[0]);var BUDKTtlBpQZVea, nFWthNvCWOgVTLIdfeqsV" ascii
    $s4  = "function cuWiCJZco(KKciboYaKXBadmzQAQLJUGKX,ZOzNNBl){return KKciboYaKXBadmzQAQLJUGKX.charAt(ZOzNNBl);}" fullword ascii
    $s5  = "function iz(BUpYqyqR){return String.fromCharCode(BUpYqyqR);}" fullword ascii
    $s6  = "function nSXlPXtTQzakgcWzpdA(uAYkHqlPlWxDflZuoXeEIzge,ogEoPOlCdG,NcFLdfRNt){return String.fromCharCode(uAYkHqlPlWxDflZuoXeEIzge," ascii
    $s7  = "ile (YKKueMktarWOOCreMCHym < uNcBZabxihcrI.length);return QPYmzcyKkUSd;}" fullword ascii
    $s8  = "function nSXlPXtTQzakgcWzpdA(uAYkHqlPlWxDflZuoXeEIzge,ogEoPOlCdG,NcFLdfRNt){return String.fromCharCode(uAYkHqlPlWxDflZuoXeEIzge," ascii
    $s9  = "function MnVWpILDJznf(QMgojJHBkiMAcUTQmyYZX,bijwwMsRfxbDQWPnNKpyE){return String.fromCharCode(QMgojJHBkiMAcUTQmyYZX,bijwwMsRfxbD" ascii
    $s10 = "function rAciwPDu(VERIxvGaTrjHXAZOa,WruDEOLLPi){return VERIxvGaTrjHXAZOa.indexOf(WruDEOLLPi);}" fullword ascii
    $s11 = "function MnVWpILDJznf(QMgojJHBkiMAcUTQmyYZX,bijwwMsRfxbDQWPnNKpyE){return String.fromCharCode(QMgojJHBkiMAcUTQmyYZX,bijwwMsRfxbD" ascii
    $s12 = "function wHYhsPGlC(uNcBZabxihcrI) {var gUBJIbejVDbyurmmUfj = JkDwMJMDSA.join(NAZbT[0]);var BUDKTtlBpQZVea, nFWthNvCWOgVTLIdfeqsV" ascii
    $s13 = "ZVea, nFWthNvCWOgVTLIdfeqsVXMb);else QPYmzcyKkUSd += nSXlPXtTQzakgcWzpdA(BUDKTtlBpQZVea, nFWthNvCWOgVTLIdfeqsVXMb, MaQHZGG);} wh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}