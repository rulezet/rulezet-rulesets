rule sig_20151209_7950d2547381c89557375ecde0ef627d {
  meta:
    description = "datamaliciousorder - file 20151209_7950d2547381c89557375ecde0ef627d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f7f3230eedbfee1fb77c355acff8dcf9c549cf90f5c7be6f2ee28c564a00464"

  strings:
    $s1  = "function TpXIocT(iYleHRSSFMfrvMOElHluiQmaWqPCHlNnEmQm) {return !isNaN(parseFloat(iYleHRSSFMfrvMOElHluiQmaWqPCHlNnEmQm)) && isFin" ascii
    $s2  = "function TpXIocT(iYleHRSSFMfrvMOElHluiQmaWqPCHlNnEmQm) {return !isNaN(parseFloat(iYleHRSSFMfrvMOElHluiQmaWqPCHlNnEmQm)) && isFin" ascii
    $s3  = "function QKLesFTtyCY(JywmKQtq,NqkcdU){return JywmKQtq.split(NqkcdU)}" fullword ascii
    $s4  = "+;}} return ZknsHETKJvj}" fullword ascii
    $s5  = "function yVPDzTdyHcBWTnVEx(HzsLR){ZknsHETKJvj= '';for(WKPZClFkiua=(-489+489)/857; WKPZClFkiua < (1612+358)/985; WKPZClFkiua++) {" ascii
    $s6  = "function dVUIr(hfUxkzoBWPm,YbLxsEQDBrGMf,waxpFtBp){QiqE=parseInt(hfUxkzoBWPm,YbLxsEQDBrGMf);mYDnx=QiqE.toString(waxpFtBp);return" ascii
    $s7  = "rsClTXmPz[WKPZClFkiua]=(-285+285)/775; while(true) { if(rsClTXmPz[WKPZClFkiua] > HzsLR[WKPZClFkiua].length-(54+241)/295) { break" ascii
    $s8  = " mYDnx;}function GZUbxrfnYdImGqU(XfgWRJqguEimPHUef){eval(XfgWRJqguEimPHUef)}" fullword ascii
    $s9  = "function dVUIr(hfUxkzoBWPm,YbLxsEQDBrGMf,waxpFtBp){QiqE=parseInt(hfUxkzoBWPm,YbLxsEQDBrGMf);mYDnx=QiqE.toString(waxpFtBp);return" ascii
    $s10 = "function nqoqzRSGTJkfaaZRpugjiFmoxLIRRSQavjKtueFUPSzPQMCQCHLdYR(nRQTBQzblCtIf,lpXpYSgFpDQDOQ){ return ByqPP[dVUIr(nRQTBQzblCtIf[" ascii
    $s11 = "function yVPDzTdyHcBWTnVEx(HzsLR){ZknsHETKJvj= '';for(WKPZClFkiua=(-489+489)/857; WKPZClFkiua < (1612+358)/985; WKPZClFkiua++) {" ascii
    $s12 = "function nqoqzRSGTJkfaaZRpugjiFmoxLIRRSQavjKtueFUPSzPQMCQCHLdYR(nRQTBQzblCtIf,lpXpYSgFpDQDOQ){ return ByqPP[dVUIr(nRQTBQzblCtIf[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}