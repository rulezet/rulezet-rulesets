rule sig_20151210_4d8a3ef2d9b8c46b82b08e8ecad20196 {
  meta:
    description = "datamaliciousorder - file 20151210_4d8a3ef2d9b8c46b82b08e8ecad20196.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "711192425313f5ba01f4173245c80e51425b495995f360a8f686a6852c55c20d"

  strings:
    $s1  = "function qlkJgDo(qNScbgWDxnoJYMUlMgJmmkMEYkMPvKXPbXmF) {return !isNaN(parseFloat(qNScbgWDxnoJYMUlMgJmmkMEYkMPvKXPbXmF)) && isFin" ascii
    $s2  = "function qlkJgDo(qNScbgWDxnoJYMUlMgJmmkMEYkMPvKXPbXmF) {return !isNaN(parseFloat(qNScbgWDxnoJYMUlMgJmmkMEYkMPvKXPbXmF)) && isFin" ascii
    $s3  = "qEYLTIGw[iWrkGluyFZq]=(-477+477)/936; while(true) { if(RqEYLTIGw[iWrkGluyFZq] > oLidW[iWrkGluyFZq].length-(14+733)/747) { break;" ascii
    $s4  = "function MxWTXgXTCmYZfjNwk(oLidW){bFpNubVCQwp= '';for(iWrkGluyFZq=(-687+687)/921; iWrkGluyFZq < (147+393)/270; iWrkGluyFZq++) {R" ascii
    $s5  = "} return bFpNubVCQwp}" fullword ascii
    $s6  = "OsuDVaS=(-447+447)/114;while(true){if(OsuDVaS>=(76714+854)/606){break;}dtjenPRcdgJRO[OsuDVaS]=String.fromCharCode(OsuDVaS);OsuDV" ascii
    $s7  = " QOnVZ;}function QLnPhMkgeiluplA(dBluSYBmhldrteJDJ){eval(dBluSYBmhldrteJDJ)}" fullword ascii
    $s8  = "function ccuQZtTBnnA(DzbKcjrs,XMiueL){return DzbKcjrs.split(XMiueL)}" fullword ascii
    $s9  = "function OhHURWNojHMXbwoanDrKsGbxKIRgcITUjNrLyXQSBMgdQITNRjDkNE(QtRXeEGbBBeWw,lUxhaSgwYBNFOw){ return dtjenPRcdgJRO[FmzzJ(QtRXeE" ascii
    $s10 = "OsuDVaS=(-447+447)/114;while(true){if(OsuDVaS>=(76714+854)/606){break;}dtjenPRcdgJRO[OsuDVaS]=String.fromCharCode(OsuDVaS);OsuDV" ascii
    $s11 = "function FmzzJ(PYXmSiAjgpN,zHLmUrgFYAcPD,HOaNvNxt){TPgK=parseInt(PYXmSiAjgpN,zHLmUrgFYAcPD);QOnVZ=TPgK.toString(HOaNvNxt);return" ascii
    $s12 = "function OhHURWNojHMXbwoanDrKsGbxKIRgcITUjNrLyXQSBMgdQITNRjDkNE(QtRXeEGbBBeWw,lUxhaSgwYBNFOw){ return dtjenPRcdgJRO[FmzzJ(QtRXeE" ascii
    $s13 = "function MxWTXgXTCmYZfjNwk(oLidW){bFpNubVCQwp= '';for(iWrkGluyFZq=(-687+687)/921; iWrkGluyFZq < (147+393)/270; iWrkGluyFZq++) {R" ascii
    $s14 = "function FmzzJ(PYXmSiAjgpN,zHLmUrgFYAcPD,HOaNvNxt){TPgK=parseInt(PYXmSiAjgpN,zHLmUrgFYAcPD);QOnVZ=TPgK.toString(HOaNvNxt);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}