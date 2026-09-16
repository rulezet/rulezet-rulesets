rule sig_20160316_3b9ac9d1c1cc1034a2304ac3bb66855c {
  meta:
    description = "datamaliciousorder - file 20160316_3b9ac9d1c1cc1034a2304ac3bb66855c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a455228586a7590624c62e2ac4f644a8729025f36ebc5af64b82cb1b262b93ae"

  strings:
    $s1 = "while (FXwpaP[MtAlUTOLzhwnk + QSBFJCEdk + cftb + sQfypkW] < 4 ) {WScript[pJHTOcRpyVRRhv + kOpyrrVh + DgXswPv](1000)};" fullword ascii
    $s2 = "function yVWDmkJkjGlv(n){return sVlfqRyjnyLXY + asbMO + RApJCpCjAo + xSygULjD + ZcPcc + wVRYskzZINTvj + zdZbqVaE + ELsjjRuFDZo;}" ascii
    $s3 = "+ nkbUZtpgAd + fOVXmsTLJZbQ + ZQPl + sjYGjJtqyc + VtYqP + vynr, false);" fullword ascii
    $s4 = "FXwpaP[SPzCNHGTlcGMB + HdMzmi](aKevrcBKriHmU, tUKGz + tsjIdmkdehX + lIPqhSDn + unBkBqVlPo + nne + ksQPkbRUCQjk + omKywuLvwczsYY " ascii
    $s5 = "function FgKTArfKnSWH(zSKPwC){ILS[UnN + tDPQWH](zSKPwC, 0, 0);}" fullword ascii
    $s6 = "var fJDZwzCFFYvtqB = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}