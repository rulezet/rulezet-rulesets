rule sig_20160526_8d38f99095348468dff0b7d8fa25f43c {
  meta:
    description = "datamaliciousorder - file 20160526_8d38f99095348468dff0b7d8fa25f43c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ecfc5ec33e547ae6f92c2bc9be522302cc1add8f8e6e602c0852102c38fe9e4"

  strings:
    $s1  = "(Math.sin(274), 2) + Math.pow(Math.cos(274), 2) - 1))-664) & 0xff;CCueuvDINJFIdxzI = gKphSzhTn>> (40 + Math.round((Math.pow(Math" ascii
    $s2  = "und((Math.pow(Math.sin(287), 2) + Math.pow(Math.cos(287), 2) - 1))-895)) SjvNcA += fxY(HSYMuSnU);else if (PfaUdhEGfLqaIACo == (7" ascii
    $s3  = "function WLbZrySmT(NhqdeHbmDBBwt) {var GPOmJdBAlgGXcH = iIRmZSxL.join(SDYUwyng[0]);var HSYMuSnU, CCueuvDINJFIdxzI, QuHJzhcsEPTDW" ascii
    $s4  = "function OfrmwbZPWALbJ(vSTTCnFFroQts,ltpOInZSkrSVkcurC){return vSTTCnFFroQts.charAt(ltpOInZSkrSVkcurC);}" fullword ascii
    $s5  = "function HVlzgStoEzxD(umpSGiAVrbepSxNTj,GTviIqWXXwKOO,wYXtDicMrpTWsvKgGTlQc){return String.fromCharCode(umpSGiAVrbepSxNTj,GTviIq" ascii
    $s6  = "function fxY(QmTgtZ){return String.fromCharCode(QmTgtZ);}" fullword ascii
    $s7  = "function sWrdwdrjObnJzHXjjRMaXRQf(yfpMcfPflvfkNpzHFplXgy,tuYdoEENafAtfn){return String.fromCharCode(yfpMcfPflvfkNpzHFplXgy,tuYdo" ascii
    $s8  = "function cNfzD(FoPmaVRdi,jaUjTIoJvRBrqj){return FoPmaVRdi.indexOf(jaUjTIoJvRBrqj);}" fullword ascii
    $s9  = "function sWrdwdrjObnJzHXjjRMaXRQf(yfpMcfPflvfkNpzHFplXgy,tuYdoEENafAtfn){return String.fromCharCode(yfpMcfPflvfkNpzHFplXgy,tuYdo" ascii
    $s10 = "function HVlzgStoEzxD(umpSGiAVrbepSxNTj,GTviIqWXXwKOO,wYXtDicMrpTWsvKgGTlQc){return String.fromCharCode(umpSGiAVrbepSxNTj,GTviIq" ascii
    $s11 = "function WLbZrySmT(NhqdeHbmDBBwt) {var GPOmJdBAlgGXcH = iIRmZSxL.join(SDYUwyng[0]);var HSYMuSnU, CCueuvDINJFIdxzI, QuHJzhcsEPTDW" ascii
    $s12 = "bmDBBwt.length);return SjvNcA;}" fullword ascii
    $s13 = ", CCueuvDINJFIdxzI);else SjvNcA += HVlzgStoEzxD(HSYMuSnU, CCueuvDINJFIdxzI, QuHJzhcsEPTDWCOYT);} while (EfQZUlkoOllhlnl < NhqdeH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}