rule sig_20160526_155932564e8b012abb5003069cabb1c8 {
  meta:
    description = "datamaliciousorder - file 20160526_155932564e8b012abb5003069cabb1c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e648f87d54bd90b8ab25fc57a5485e645aa2e40562bce548be95232880fe0da6"

  strings:
    $s1  = "ath.sin(963), 2) + Math.pow(Math.cos(963), 2) - 1))-835)) mLHCvdeWKEOsrZrcgyiCDt += kSZsWyZmDE(KmJFvD, wLqLLmsuidCtbgoIxW);else " ascii
    $s2  = "function GgbiD(UsSSrtZreoUVa) {var loklCuiqlWS = cBjowXUZxuX.join(fuPUnlaCtzF[0]);var KmJFvD, wLqLLmsuidCtbgoIxW, OYYcOyjvF, Fxr" ascii
    $s3  = "(614), 2) + Math.pow(Math.cos(614), 2) - 1))-972) | NtSGHJ;KmJFvD = UWNVx>> (490 + Math.round((Math.pow(Math.sin(39), 2) + Math." ascii
    $s4  = ") + Math.pow(Math.cos(132), 2) - 1))-891)) mLHCvdeWKEOsrZrcgyiCDt += mI(KmJFvD);else if (NtSGHJ == (899 + Math.round((Math.pow(M" ascii
    $s5  = "pow(Math.cos(39), 2) - 1))-474) & 0xff;wLqLLmsuidCtbgoIxW = UWNVx>> (66 + Math.round((Math.pow(Math.sin(529), 2) + Math.pow(Math" ascii
    $s6  = "function mzeyttnpQwpmZT(aLFxevKKs,KwtSrOls){return aLFxevKKs.charAt(KwtSrOls);}" fullword ascii
    $s7  = "function vRtJITeFusJpFb(eOSLZMtsIRbOXKafgliEmZ,kCukbuwRcqdJFexywulPYZLV,shKqf){return String.fromCharCode(eOSLZMtsIRbOXKafgliEmZ" ascii
    $s8  = "function kSZsWyZmDE(duwshvCIqjwGlbVHNbHVr,xIpbQp){return String.fromCharCode(duwshvCIqjwGlbVHNbHVr,xIpbQp);}" fullword ascii
    $s9  = "mLHCvdeWKEOsrZrcgyiCDt += vRtJITeFusJpFb(KmJFvD, wLqLLmsuidCtbgoIxW, OYYcOyjvF);} while (IevGWwEQyHsJwfPgpQfwJ < UsSSrtZreoUVa.l" ascii
    $s10 = "function vRtJITeFusJpFb(eOSLZMtsIRbOXKafgliEmZ,kCukbuwRcqdJFexywulPYZLV,shKqf){return String.fromCharCode(eOSLZMtsIRbOXKafgliEmZ" ascii
    $s11 = "function GgbiD(UsSSrtZreoUVa) {var loklCuiqlWS = cBjowXUZxuX.join(fuPUnlaCtzF[0]);var KmJFvD, wLqLLmsuidCtbgoIxW, OYYcOyjvF, Fxr" ascii
    $s12 = "function mI(dbiyhLKmnu){return String.fromCharCode(dbiyhLKmnu);}" fullword ascii
    $s13 = "function aVoKXJsx(IFJxdhSacSSuClDV,nrmaUXSElgwLKDsjWYHTVT){return IFJxdhSacSSuClDV.indexOf(nrmaUXSElgwLKDsjWYHTVT);}" fullword ascii
    $s14 = "ength);return mLHCvdeWKEOsrZrcgyiCDt;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}