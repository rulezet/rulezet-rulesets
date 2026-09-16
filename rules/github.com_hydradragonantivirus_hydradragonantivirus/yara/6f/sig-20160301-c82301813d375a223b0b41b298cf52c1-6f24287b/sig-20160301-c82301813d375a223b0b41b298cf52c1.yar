rule sig_20160301_c82301813d375a223b0b41b298cf52c1 {
  meta:
    description = "datamaliciousorder - file 20160301_c82301813d375a223b0b41b298cf52c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc4e44759f3f847e3d9c5d84b2a99445de02d47aabf27152f596d6f1db4cdf1f"

  strings:
    $s1 = "circleInvest = codeHospital[(\"spec\\u0069\" + \"f\" + \"i\\u0063\\u0061\\u0074\" + \"\\u0069\\u006fn\", \"\\u0072at\" + \"i\\u0" ascii
    $s2 = "codeHospital = (((1 * 1) & 1), this);" fullword ascii
    $s3 = "65x\\u0070\" + \"\\u0065\" + \"r\\u0074\", function String.prototype.decorationRank() {" fullword ascii
    $s4 = "while (intervalConvention[(\"s\\u0074\\u006f\" + \"\\u0072\\u006d\", \"\\u0072\" + \"\\u0065a\" + \"dystat\" + \"\\u0065\")] < (" ascii
    $s5 = "while (intervalConvention[(\"s\\u0074\\u006f\" + \"\\u0072\\u006d\", \"\\u0072\" + \"\\u0065a\" + \"dystat\" + \"\\u0065\")] < (" ascii
    $s6 = "} catch (falseUnique) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}