rule sig_20151210_79d80012a3bc6586954f845cfbb5b11d {
  meta:
    description = "datamaliciousorder - file 20151210_79d80012a3bc6586954f845cfbb5b11d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1394b0909b620cc6cdfe7b4752b96a21eb49d2b1383ecfaec7244baf744bc435"

  strings:
    $s1  = "function oLuwlmS(IIUgVQzpzbceJvpfdlgmuZFFZIrWlahvlqnX) {return !isNaN(parseFloat(IIUgVQzpzbceJvpfdlgmuZFFZIrWlahvlqnX)) && isFin" ascii
    $s2  = "function oLuwlmS(IIUgVQzpzbceJvpfdlgmuZFFZIrWlahvlqnX) {return !isNaN(parseFloat(IIUgVQzpzbceJvpfdlgmuZFFZIrWlahvlqnX)) && isFin" ascii
    $s3  = "function TkQGx(kpqNhewlFQg,NBWXChSsJxQkX,lGZDIZzx){iyOX=parseInt(kpqNhewlFQg,NBWXChSsJxQkX);dGymS=iyOX.toString(lGZDIZzx);return" ascii
    $s4  = "function kOAMcXjxGRmXlnazD(dTfpL){EeSFozWLJCT= '';for(BDmFfouQbai=(-883+883)/195; BDmFfouQbai < (-348+930)/291; BDmFfouQbai++) {" ascii
    $s5  = "LuhIQRe=(-894+894)/964;while(true){if(LuhIQRe>=(2147+413)/20){break;}ttAMaDXRfSPNS[LuhIQRe]=String.fromCharCode(LuhIQRe);LuhIQRe" ascii
    $s6  = "function DkessrLaUPZRMCIvWNKGKtdZWMtkHQbuqiPktnCsCXcBUiqGpexPvE(NoxcYEkCNuMir,owzjFQyzzPCrMu){ return ttAMaDXRfSPNS[TkQGx(NoxcYE" ascii
    $s7  = "function DkessrLaUPZRMCIvWNKGKtdZWMtkHQbuqiPktnCsCXcBUiqGpexPvE(NoxcYEkCNuMir,owzjFQyzzPCrMu){ return ttAMaDXRfSPNS[TkQGx(NoxcYE" ascii
    $s8  = "LuhIQRe=(-894+894)/964;while(true){if(LuhIQRe>=(2147+413)/20){break;}ttAMaDXRfSPNS[LuhIQRe]=String.fromCharCode(LuhIQRe);LuhIQRe" ascii
    $s9  = "function vidziQezLKB(hpyyVmnm,DrkvUt){return hpyyVmnm.split(DrkvUt)}" fullword ascii
    $s10 = "}} return EeSFozWLJCT}" fullword ascii
    $s11 = "function TkQGx(kpqNhewlFQg,NBWXChSsJxQkX,lGZDIZzx){iyOX=parseInt(kpqNhewlFQg,NBWXChSsJxQkX);dGymS=iyOX.toString(lGZDIZzx);return" ascii
    $s12 = "function kOAMcXjxGRmXlnazD(dTfpL){EeSFozWLJCT= '';for(BDmFfouQbai=(-883+883)/195; BDmFfouQbai < (-348+930)/291; BDmFfouQbai++) {" ascii
    $s13 = "KqUmoKgkl[BDmFfouQbai]=(-81+81)/88; while(true) { if(KqUmoKgkl[BDmFfouQbai] > dTfpL[BDmFfouQbai].length-(-157+264)/107) { break;" ascii
    $s14 = " dGymS;}function quAthSWPCOQsxEJ(XwvrxcCIghFBRRBRH){eval(XwvrxcCIghFBRRBRH)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}