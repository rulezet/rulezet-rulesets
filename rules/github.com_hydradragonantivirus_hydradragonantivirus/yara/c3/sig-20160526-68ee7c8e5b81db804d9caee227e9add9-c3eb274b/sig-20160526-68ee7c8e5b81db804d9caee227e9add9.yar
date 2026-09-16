rule sig_20160526_68ee7c8e5b81db804d9caee227e9add9 {
  meta:
    description = "datamaliciousorder - file 20160526_68ee7c8e5b81db804d9caee227e9add9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "116259e18d490fb67bfc4d5508c58d4372abb2bbe2357b6f0a27409dd15866cf"

  strings:
    $s1  = ") - 1))-797)) SDnaEbqMmVhJZtMS += cY(nQAxB);else if (mMBMKzQBt == (813 + Math.round((Math.pow(Math.sin(524), 2) + Math.pow(Math." ascii
    $s2  = "cos(524), 2) - 1))-749)) SDnaEbqMmVhJZtMS += FPnPKeddPxUenspEjYTqt(nQAxB, ohuwiBzJeMuUSiHFMWzxKqhb);else SDnaEbqMmVhJZtMS += fYw" ascii
    $s3  = "function XttylEnjp(UtjlqFGJmgREx) {var fSCpuKiIAJGOYnnGOe = dIplWJrFMYth.join(gznLlwehWcGVhGogXIfcvzH[0]);var nQAxB, ohuwiBzJeMu" ascii
    $s4  = "function sVxwRuxechzhupYSeCTEtoHt(DQQeYWdkMiEONUGDRT,ENLgurJHKUthobpJrrBEr){return DQQeYWdkMiEONUGDRT.charAt(ENLgurJHKUthobpJrrB" ascii
    $s5  = "function sVxwRuxechzhupYSeCTEtoHt(DQQeYWdkMiEONUGDRT,ENLgurJHKUthobpJrrBEr){return DQQeYWdkMiEONUGDRT.charAt(ENLgurJHKUthobpJrrB" ascii
    $s6  = "function fYwGLiRrrEh(milIHdVsNSuTpU,ujhokwTKanw,iRWDMCbcuzJAwf){return String.fromCharCode(milIHdVsNSuTpU,ujhokwTKanw,iRWDMCbcuz" ascii
    $s7  = "function FPnPKeddPxUenspEjYTqt(KWKWvTISGRSDGYWSxtCDQ,SfJeAlOstDnPExRgVb){return String.fromCharCode(KWKWvTISGRSDGYWSxtCDQ,SfJeAl" ascii
    $s8  = "function XttylEnjp(UtjlqFGJmgREx) {var fSCpuKiIAJGOYnnGOe = dIplWJrFMYth.join(gznLlwehWcGVhGogXIfcvzH[0]);var nQAxB, ohuwiBzJeMu" ascii
    $s9  = "function fYwGLiRrrEh(milIHdVsNSuTpU,ujhokwTKanw,iRWDMCbcuzJAwf){return String.fromCharCode(milIHdVsNSuTpU,ujhokwTKanw,iRWDMCbcuz" ascii
    $s10 = "GLiRrrEh(nQAxB, ohuwiBzJeMuUSiHFMWzxKqhb, zCswMJPGpaRYClTacLhF);} while (vJNStcjrWoSGFO < UtjlqFGJmgREx.length);return SDnaEbqMm" ascii
    $s11 = "function cY(CNejxufMPvAglraYUYVkcSQ){return String.fromCharCode(CNejxufMPvAglraYUYVkcSQ);}" fullword ascii
    $s12 = "function FPnPKeddPxUenspEjYTqt(KWKWvTISGRSDGYWSxtCDQ,SfJeAlOstDnPExRgVb){return String.fromCharCode(KWKWvTISGRSDGYWSxtCDQ,SfJeAl" ascii
    $s13 = "function MraITyjcTheWca(afOPtPhLDRtbbBHGsD,LvggReNMGlbveygL){return afOPtPhLDRtbbBHGsD.indexOf(LvggReNMGlbveygL);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}