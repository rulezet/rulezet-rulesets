rule sig_20160526_fdd80865f76826b54612bb6ac09fd993 {
  meta:
    description = "datamaliciousorder - file 20160526_fdd80865f76826b54612bb6ac09fd993.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7066b8d2680dd5b60a6499b9f33d5b30b1d702d15626b3f833bf908ff9d58786"

  strings:
    $s1  = "function PdSDYMZvOXO(dEzGqgwefyHDR) {var bWCDVmbFkl = rkzlklFANHldbJqJZ.join(jzviI[0]);var MXDmhhEUJdstqaSVevs, dQaaHhPScovIT, l" ascii
    $s2  = "th.pow(Math.cos(19), 2) - 1))-531)) xiRHntTYZxoMeCkTO += HgigMuRbdHxgjVbGmIhRpHU(MXDmhhEUJdstqaSVevs, dQaaHhPScovIT);else xiRHnt" ascii
    $s3  = ") - 1))-494)) xiRHntTYZxoMeCkTO += Ie(MXDmhhEUJdstqaSVevs);else if (oPHIZkP == (595 + Math.round((Math.pow(Math.sin(19), 2) + Ma" ascii
    $s4  = "function SnVgxNOgK(PpaVOjADTzVcHMU,OkrbSjst){return PpaVOjADTzVcHMU.charAt(OkrbSjst);}" fullword ascii
    $s5  = "function MKDLQqNnkqQiWKpZpxjGARaT(OHxZum,tEzmmvbGucfGyfdSnSvU){return OHxZum.indexOf(tEzmmvbGucfGyfdSnSvU);}" fullword ascii
    $s6  = "efyHDR.length);return xiRHntTYZxoMeCkTO;}" fullword ascii
    $s7  = "function HgigMuRbdHxgjVbGmIhRpHU(jkokexRIksOd,kOTdrljSpeKbScfLvnSxT){return String.fromCharCode(jkokexRIksOd,kOTdrljSpeKbScfLvnS" ascii
    $s8  = "function RTCUFyvbmUxRsChgEsQI(mUyah,wmrhzuvBTZfr,hHMjnDANOcdaTOzMx){return String.fromCharCode(mUyah,wmrhzuvBTZfr,hHMjnDANOcdaTO" ascii
    $s9  = "TYZxoMeCkTO += RTCUFyvbmUxRsChgEsQI(MXDmhhEUJdstqaSVevs, dQaaHhPScovIT, lGPYUDHyNsQMtaBHXYLiMlJd);} while (TKsEGUOGXpk < dEzGqgw" ascii
    $s10 = "function PdSDYMZvOXO(dEzGqgwefyHDR) {var bWCDVmbFkl = rkzlklFANHldbJqJZ.join(jzviI[0]);var MXDmhhEUJdstqaSVevs, dQaaHhPScovIT, l" ascii
    $s11 = "function RTCUFyvbmUxRsChgEsQI(mUyah,wmrhzuvBTZfr,hHMjnDANOcdaTOzMx){return String.fromCharCode(mUyah,wmrhzuvBTZfr,hHMjnDANOcdaTO" ascii
    $s12 = "function HgigMuRbdHxgjVbGmIhRpHU(jkokexRIksOd,kOTdrljSpeKbScfLvnSxT){return String.fromCharCode(jkokexRIksOd,kOTdrljSpeKbScfLvnS" ascii
    $s13 = "function Ie(ZdXqFKvHDrtnlCcBrb){return String.fromCharCode(ZdXqFKvHDrtnlCcBrb);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}