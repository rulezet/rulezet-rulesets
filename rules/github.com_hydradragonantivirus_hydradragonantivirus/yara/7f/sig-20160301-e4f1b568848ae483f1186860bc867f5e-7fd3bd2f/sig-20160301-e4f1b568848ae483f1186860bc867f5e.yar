rule sig_20160301_e4f1b568848ae483f1186860bc867f5e {
  meta:
    description = "datamaliciousorder - file 20160301_e4f1b568848ae483f1186860bc867f5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1858a6a6265e4496f909e0ae0fac6d7a7772ea5a2152d77d7d293961556284b8"

  strings:
    $s1 = "while(operaSymptom[(\"di\\u0073\" + \"pat\" + \"\\u0063h\" + \"\\u0065\\u0072\", \"\\u0070\\u006f\\u0073\\u0069\" + \"tion\", \"" ascii
    $s2 = "while(operaSymptom[(\"di\\u0073\" + \"pat\" + \"\\u0063h\" + \"\\u0065\\u0072\", \"\\u0070\\u006f\\u0073\\u0069\" + \"tion\", \"" ascii
    $s3 = "parityBand = (((0 & 1) | (1 * 1)), this);" fullword ascii
    $s4 = "6or\\u006d\") + (\"\\u0073\\u006f\" + \"\\u006ci\" + \"d\", \"i\\u006es\\u0074r\\u0075\" + \"c\\u0074i\" + \"\\u006f\\u006e\", f" ascii
    $s5 = "absoluteCanal = perspectiveModify[(\"c\" + \"\\u006f\\u006d\\u006de\\u0072\\u0063\" + \"e\", \"\\u0063o\" + \"mm\\u0061\\u006e" ascii
    $s6 = "} catch(computerSymmetry) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    all of them
}