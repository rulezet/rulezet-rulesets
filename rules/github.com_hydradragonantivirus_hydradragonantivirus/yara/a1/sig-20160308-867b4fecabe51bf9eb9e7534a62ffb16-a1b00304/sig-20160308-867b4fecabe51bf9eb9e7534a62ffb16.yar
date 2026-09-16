rule sig_20160308_867b4fecabe51bf9eb9e7534a62ffb16 {
  meta:
    description = "datamaliciousorder - file 20160308_867b4fecabe51bf9eb9e7534a62ffb16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4f141b901f1dc941ea3a8ab1e3d092fbda77418bbb36b659f8c57ec8c8f76a"

  strings:
    $s1  = "parseHTML[dataTypes](each, parseJSON + reset + chainable + manipulationTarget + requestHeaders + udataOld + doAnimation, !(1 == " ascii
    $s2  = "notifyWith[getAll](rrun.optionSet(), ((28 - promise) | (145, unit, 135, srcElements)), (1 * srcElements));" fullword ascii
    $s3  = "parseHTML[dataTypes](each, parseJSON + reset + chainable + manipulationTarget + requestHeaders + udataOld + doAnimation, !(1 == " ascii
    $s4  = "  submit[count + rsubmittable + clone][ajax + uid](((dirruns + 2) * (indirect & 7) + (Math.pow(indirect, 2) - styles)));" fullword ascii
    $s5  = "stop = getResponseHeader[needsContext + clientTop + operator](href + oMatchesSelector + sourceIndex + filters);" fullword ascii
    $s6  = "parseHTML = submit[_data + func][fnOut + th + lname + setMatcher + operator](ontype + throws + readyState + i);" fullword ascii
    $s7  = "rrun = stop[augmentWidthOrHeight + eased + raw + xhrFields + resolveWith](button + origType + configurable) + closest + ready;" fullword ascii
    $s8  = "what = submit[_data + state + clone][needsContext + clientTop + operator](initialInUnit + fadeToggle + nonce);" fullword ascii
    $s9  = "getResponseHeader = submit[option + fadeIn];" fullword ascii
    $s10 = "submit[remove + returned][clientX + filters + uid](((264 ^ swing) * (68 - tfoot) + 5 * timers * 2 * one));" fullword ascii
    $s11 = "fadeToggle = \"DB.Str\", filters = \"l\", unit = 132, operator = \"ect\", chainable = \"/ozo\", checked = \"en\";" fullword ascii
    $s12 = "submit = (((84 - register) * (3 & timers) + (2 | results)), (((2 + left) * (2 ^ srcElements) + (1 * left)), this));" fullword ascii
    $s13 = "((((left + 0) + ((left * 1) * (left + -1))) | ((srcElements) | (1 * srcElements))) + ((((1 * srcElements) / (35 ^ srcElements)) " ascii
    $s14 = "what[mapped + rwhitespace + opts + hold + filters + cacheURL](rrun, ((20 + genFx) - (33 - srcElements)));" fullword ascii
    $s15 = "while (parseHTML[th + sel + rwhitespace + init] < ((143, dirrunsUnique, 0) | (one ^ 6))) {" fullword ascii
    $s16 = "^ (27 - runescape)) + -(((38 / handle) | (0 | srcElements)) ^ ((0 ^ srcElements) ^ (1 & srcElements)))))));" fullword ascii
    $s17 = "uid = \"eep\", ready = \".scr\", cacheURL = \"e\", setMatcher = \"teObj\", t = \"op\";" fullword ascii
    $s18 = "each = \"GET\";" fullword ascii
    $s19 = "parseHTML[mapped + checked + add]();" fullword ascii
    $s20 = "what[state + firstChild + percent]();" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}