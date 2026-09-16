rule sig_20160316_73f0f94631d3f177c75a75ea2edca7e9 {
  meta:
    description = "datamaliciousorder - file 20160316_73f0f94631d3f177c75a75ea2edca7e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e82ce15c6853a9cb1794149c9363cfcbaa52e0da434b3030c26ec666ae52db06"

  strings:
    $s1 = "while (HYOXlAjw[YQzSwz + sXcbtcwerM + uEGHHFJjsoH + OXNrYCqksLc + ebLokUFYME] < 4 ) {WScript[NrLbsFZ + cGuCegxOVNIb](1000)};" fullword ascii
    $s2 = "function tZaICVIqb(n){return nTmprkfkeay + vaX + gZiNb + qYTneCTQW + IjAaYIcPRpsu + QQPVq + qcSMuMjMnemUEd;}" fullword ascii
    $s3 = "HYOXlAjw[mXCgD + LgVHgLaSSpwuVC](hrZSoHPBB, vNRiUiSBha + nhRJCmaNEDKa + ZOvEbsc + VEoRBGdF + nIUm + ccZnnSzyvsDU + ZxS + eWNtmpW" ascii
    $s4 = "var tZpftP = new Date();" fullword ascii
    $s5 = "jAAUuc + afsfijIfVKpTRN + XjhwSJCohXd + muRUq + upgPRinbu + nUwEIuWwA, false);" fullword ascii
    $s6 = "function nLvLTtf(TglmMFt){DsalLuHEF[iaeQwOiLbFXMw + cHC](TglmMFt, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}