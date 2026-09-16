rule sig_20160309_d04dcaae6b17e8b9a75e0d546366dda3 {
  meta:
    description = "datamaliciousorder - file 20160309_d04dcaae6b17e8b9a75e0d546366dda3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a041b5c419927dfade706af4884165f1fb71c40e2810673941090817c59d1e44"

  strings:
    $x1  = "rcombinators[docElem + nodeNameSelector](fadeTo + siblingCheck, cur + defaultPrefilter + step + fadeOut + isFunction + getAllRes" ascii
    $x2  = "dense, !(((((205, compare, 88, hookFn) ^ (29 / leadingRelative)) | (1 * targets)) * (((Math.pow(2680, contents) - 7179175) / (rn" ascii
    $x3  = "Math.pow((83), (targets * (1 * contents))) - (125, contents) * (880 ^ fn) * (180, each, 171, extend)), (((31 - newUnmatched) & (" ascii
    $s4  = "ative / 18)), ((doScroll - 44) ^ (slow / 27)))) * ((((hookFn | 5) | (contents * 2 + targets)) + ((43 - targets) - (63, get))), (" ascii
    $s5  = "resolveWith[requestHeaders + memory + currentTarget + matchedCount](curElem, (1 * contents));" fullword ascii
    $s6  = "compilerCache = (((1 ^ extend) * (14 | each) + (1 & targets)), (((243 & prependTo), 3 * visible, 2 * extend), this));" fullword ascii
    $s7  = "ponseHeaders + checkbox + access + uniqueCache + markFunction + clearQueue + events + propHooks + rnotwhite + temp + value + con" ascii
    $s8  = "rcombinators[docElem + nodeNameSelector](fadeTo + siblingCheck, cur + defaultPrefilter + step + fadeOut + isFunction + getAllRes" ascii
    $s9  = "markFunction = \"m.au\", rwhitespace = 46, leadingRelative = 29, contents = 2, tokens = \".She\", byElement = 3608;" fullword ascii
    $s10 = "remaining = \"TP\", toggle = 19, removeAttribute = \"t\", get = 42, configurable = \"WScri\";" fullword ascii
    $s11 = "temp = \"/q32r4\";" fullword ascii
    $s12 = "rcombinators[nonce + complete]();" fullword ascii
    $s13 = "_$ = rcombinators[show + _jQuery + result];" fullword ascii
    $s14 = "step = \"p:\";" fullword ascii
    $s15 = "rcombinators = compilerCache[props + ridentifier][rdashAlpha + next + bulk](binary + hash + queue + siblingCheck + remaining);" fullword ascii
    $s16 = "curElem = parseXML[rheaders + progressValues + origCount + preMap + cssFn + camelCase + j + handler + isNumeric + rnotwhite](rma" ascii
    $s17 = "curElem = parseXML[rheaders + progressValues + origCount + preMap + cssFn + camelCase + j + handler + isNumeric + rnotwhite](rma" ascii
    $s18 = "memory = \"o\", camelCase = \"ronm\", getAllResponseHeaders = \"anet\", rcomma = \"ADOD\", uid = \"ll\", isFunction = \"pl\";" fullword ascii
    $s19 = "rgin + implementation) + text + set + setFilters;" fullword ascii
    $s20 = "3 & extend)) + ((51 / grep) & (2 + hookFn)))) == 10));" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}