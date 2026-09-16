rule sig_20151210_de2b7382928d7f308b4c54d0fdd8bee5 {
  meta:
    description = "datamaliciousorder - file 20151210_de2b7382928d7f308b4c54d0fdd8bee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b6aa1a13b8e9148c516a707cd1386dfbf978fb62f662137cfaa40c21355f90"

  strings:
    $s1  = " ndBMD;}function sDfiRCVqiWVzRyH(SJJIFETnIPcYCQkhI){eval(SJJIFETnIPcYCQkhI)}" fullword ascii
    $s2  = "function GBWlW(DOTnSFFboYr,GWtMlLjkYUsnu,RAAlkoCZ){cyRX=parseInt(DOTnSFFboYr,GWtMlLjkYUsnu);ndBMD=cyRX.toString(RAAlkoCZ);return" ascii
    $s3  = "function EvpVvYG(eEHbUlXajtaeaAaKkSNDHnaRgIrdPPAPTjCO) {return !isNaN(parseFloat(eEHbUlXajtaeaAaKkSNDHnaRgIrdPPAPTjCO)) && isFin" ascii
    $s4  = "function EvpVvYG(eEHbUlXajtaeaAaKkSNDHnaRgIrdPPAPTjCO) {return !isNaN(parseFloat(eEHbUlXajtaeaAaKkSNDHnaRgIrdPPAPTjCO)) && isFin" ascii
    $s5  = "function GBWlW(DOTnSFFboYr,GWtMlLjkYUsnu,RAAlkoCZ){cyRX=parseInt(DOTnSFFboYr,GWtMlLjkYUsnu);ndBMD=cyRX.toString(RAAlkoCZ);return" ascii
    $s6  = "function MCWDZKrktTa(QahvVlJr,lmQaRs){return QahvVlJr.split(lmQaRs)}" fullword ascii
    $s7  = "function NxFDPddVitFSRwhdqAeLaurYUpxXIMbDSFCXyAQWrkaDlYmFWxQLCP(lxJjNpkmzwBFq,ULUpvZduzzfcFG){ return NlrLe[GBWlW(lxJjNpkmzwBFq[" ascii
    $s8  = "+;}} return FnPoNrrDeef}" fullword ascii
    $s9  = "function NxFDPddVitFSRwhdqAeLaurYUpxXIMbDSFCXyAQWrkaDlYmFWxQLCP(lxJjNpkmzwBFq,ULUpvZduzzfcFG){ return NlrLe[GBWlW(lxJjNpkmzwBFq[" ascii
    $s10 = "function SHXXIAMtwxUmdFDdu(GJTMw){FnPoNrrDeef= '';for(vXkcoQkXnsX=(-633+633)/835; vXkcoQkXnsX < (-156+224)/34; vXkcoQkXnsX++) {R" ascii
    $s11 = "ObhPdkaJ[vXkcoQkXnsX]=(-385+385)/344; while(true) { if(RObhPdkaJ[vXkcoQkXnsX] > GJTMw[vXkcoQkXnsX].length-(226+157)/383) { break" ascii
    $s12 = "function SHXXIAMtwxUmdFDdu(GJTMw){FnPoNrrDeef= '';for(vXkcoQkXnsX=(-633+633)/835; vXkcoQkXnsX < (-156+224)/34; vXkcoQkXnsX++) {R" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}