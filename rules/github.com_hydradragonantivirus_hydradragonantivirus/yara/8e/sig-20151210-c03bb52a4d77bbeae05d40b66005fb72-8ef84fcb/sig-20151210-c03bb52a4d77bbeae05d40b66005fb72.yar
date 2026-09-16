rule sig_20151210_c03bb52a4d77bbeae05d40b66005fb72 {
  meta:
    description = "datamaliciousorder - file 20151210_c03bb52a4d77bbeae05d40b66005fb72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cae094daf01e77daa3969a99628595bf029e33afaf03dd332d620da3d4a3c1d1"

  strings:
    $s1  = "function dRJyhFW(aCbKoFGinOvRMRpYeHSSVCTWHuwDMoCSXimC) {return !isNaN(parseFloat(aCbKoFGinOvRMRpYeHSSVCTWHuwDMoCSXimC)) && isFin" ascii
    $s2  = "function dRJyhFW(aCbKoFGinOvRMRpYeHSSVCTWHuwDMoCSXimC) {return !isNaN(parseFloat(aCbKoFGinOvRMRpYeHSSVCTWHuwDMoCSXimC)) && isFin" ascii
    $s3  = "function UkIZasdJoBIfvKvyP(SeCnf){GwWePIQMsDi= '';for(fIsqXDsJyLy=(-588+588)/398; fIsqXDsJyLy < (1825+105)/965; fIsqXDsJyLy++) {" ascii
    $s4  = "++;}} return GwWePIQMsDi}" fullword ascii
    $s5  = "function aqYoAcrWtgh(MarssXcI,ZZRqAt){return MarssXcI.split(ZZRqAt)}" fullword ascii
    $s6  = "function pTDwL(fusTmIXiGNG,RjFuzujelmYyz,sDWifPFQ){YLzZ=parseInt(fusTmIXiGNG,RjFuzujelmYyz);apGjg=YLzZ.toString(sDWifPFQ);return" ascii
    $s7  = "DmwALCR=(-546+546)/111;while(true){if(DmwALCR>=(93184+768)/734){break;}BXjbmRwTJhjob[DmwALCR]=String.fromCharCode(DmwALCR);DmwAL" ascii
    $s8  = " apGjg;}function GiInXqQBByZCSvL(QqVatVAMduNHlmANo){eval(QqVatVAMduNHlmANo)}" fullword ascii
    $s9  = "ZTHUyquEO[fIsqXDsJyLy]=(-378+378)/55; while(true) { if(ZTHUyquEO[fIsqXDsJyLy] > SeCnf[fIsqXDsJyLy].length-(-199+621)/422) { brea" ascii
    $s10 = "function pTDwL(fusTmIXiGNG,RjFuzujelmYyz,sDWifPFQ){YLzZ=parseInt(fusTmIXiGNG,RjFuzujelmYyz);apGjg=YLzZ.toString(sDWifPFQ);return" ascii
    $s11 = "function UkIZasdJoBIfvKvyP(SeCnf){GwWePIQMsDi= '';for(fIsqXDsJyLy=(-588+588)/398; fIsqXDsJyLy < (1825+105)/965; fIsqXDsJyLy++) {" ascii
    $s12 = "function hwTNNHeiUhiPvkyquYamoBLkNdPeKVHrrWBUHLMOziYfTKCbuQJVNy(JAsvwZRHkJsql,ejcynBNhayZUaf){ return BXjbmRwTJhjob[pTDwL(JAsvwZ" ascii
    $s13 = "function hwTNNHeiUhiPvkyquYamoBLkNdPeKVHrrWBUHLMOziYfTKCbuQJVNy(JAsvwZRHkJsql,ejcynBNhayZUaf){ return BXjbmRwTJhjob[pTDwL(JAsvwZ" ascii
    $s14 = "DmwALCR=(-546+546)/111;while(true){if(DmwALCR>=(93184+768)/734){break;}BXjbmRwTJhjob[DmwALCR]=String.fromCharCode(DmwALCR);DmwAL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}