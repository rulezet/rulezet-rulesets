rule sig_20160526_1799e61d62726d5a9ae4a7cd98efb5f4 {
  meta:
    description = "datamaliciousorder - file 20160526_1799e61d62726d5a9ae4a7cd98efb5f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca1f8e87775afc9ac773d7b599c3067cc6415d76a381ff108c5cdbf75b1fd8e"

  strings:
    $s1  = ");else if (VvhSdUlWEhurgzaVSDdt == (525 + Math.round((Math.pow(Math.sin(405), 2) + Math.pow(Math.cos(405), 2) - 1))-461)) Dkdgek" ascii
    $s2  = "function fLnNTMcAmvUhho(rItbfOIeioXYA) {var tPYGydLsmuZrM = EHdlNkbFeJQsgwMHTmizX.join(yEndYTbOpVEoXXUCJI[0]);var QNozVidGnzZXtL" ascii
    $s3  = "function LYoCydBRetndYoY(RuuUaRoJ,JciapfwJHHZK){return RuuUaRoJ.charAt(JciapfwJHHZK);}" fullword ascii
    $s4  = "function AHFKgMwDYndSvFvoc(HOAuqRBDiZjsNA,WtecYgAdNRsrqtnxYBNOMZ,ZFGBXeoVSC){return String.fromCharCode(HOAuqRBDiZjsNA,WtecYgAdN" ascii
    $s5  = "function AHFKgMwDYndSvFvoc(HOAuqRBDiZjsNA,WtecYgAdNRsrqtnxYBNOMZ,ZFGBXeoVSC){return String.fromCharCode(HOAuqRBDiZjsNA,WtecYgAdN" ascii
    $s6  = "function rmoAh(sKLrvDjGTwoSEdFtEfOvTcop,JtyASjyqQrA){return sKLrvDjGTwoSEdFtEfOvTcop.indexOf(JtyASjyqQrA);}" fullword ascii
    $s7  = "function dPthTuLPeWsRQKEJvEh(JIUlYLPzozAMPHvJzbUlukn,OuiHvIBtIMMgATg){return String.fromCharCode(JIUlYLPzozAMPHvJzbUlukn,OuiHvIB" ascii
    $s8  = "XGFLsQSLXKoxfZyLpz += dPthTuLPeWsRQKEJvEh(QNozVidGnzZXtLdscffPDLg, gbCVVlnVOjprnTnRj);else DkdgekXGFLsQSLXKoxfZyLpz += AHFKgMwDY" ascii
    $s9  = "ndSvFvoc(QNozVidGnzZXtLdscffPDLg, gbCVVlnVOjprnTnRj, LinoGur);} while (CpCbNuWeXpXEHpdqoi < rItbfOIeioXYA.length);return DkdgekX" ascii
    $s10 = "function dPthTuLPeWsRQKEJvEh(JIUlYLPzozAMPHvJzbUlukn,OuiHvIBtIMMgATg){return String.fromCharCode(JIUlYLPzozAMPHvJzbUlukn,OuiHvIB" ascii
    $s11 = "function TC(zzYPUfbDnPyRILSeZveIWBbp){return String.fromCharCode(zzYPUfbDnPyRILSeZveIWBbp);}" fullword ascii
    $s12 = "function fLnNTMcAmvUhho(rItbfOIeioXYA) {var tPYGydLsmuZrM = EHdlNkbFeJQsgwMHTmizX.join(yEndYTbOpVEoXXUCJI[0]);var QNozVidGnzZXtL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}