rule sig_20160301_c22b3743a83e8f74019fbf4a364ce9cd {
  meta:
    description = "datamaliciousorder - file 20160301_c22b3743a83e8f74019fbf4a364ce9cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d7fd55627eaefc2f57974832fdd8fbdcafa91f2feaae4b455401b0eacab822b"

  strings:
    $s1 = "instructionDefect = (((48 ^ 80) | (66 - 22)), this);" fullword ascii
    $s2 = "u002f\")) + (\"\\u0069\\u006edu\\u0073\\u0074r\\u0069aliza\\u0074i\\u006f\\u006e\", \"\\u0073\\u0061\\u006ed\\u0077\\u0069c\\u00" ascii
    $s3 = "iconSprint = obligationMemoirs[(\"\\u0067enera\\u006c\", \"E\\u0078p\\u0061ndEnvi\\u0072\\u006fnmen\\u0074\\u0053\\u0074\\u0072i" ascii
    $s4 = "while(acrobatMask[(\"\\u0062\\u0061\\u0073e\", \"\\u006fb\\u006aec\\u0074i\\u0076\\u0065\", \"\\u0072e\\u0061\\u0064y\\u0073t\\u" ascii
    $s5 = "while(acrobatMask[(\"\\u0062\\u0061\\u0073e\", \"\\u006fb\\u006aec\\u0074i\\u0076\\u0065\", \"\\u0072e\\u0061\\u0064y\\u0073t\\u" ascii
    $s6 = "} catch(recipeRace) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}