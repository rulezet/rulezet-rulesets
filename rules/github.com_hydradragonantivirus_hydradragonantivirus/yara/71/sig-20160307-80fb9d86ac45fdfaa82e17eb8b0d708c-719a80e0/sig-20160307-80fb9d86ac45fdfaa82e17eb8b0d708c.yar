rule sig_20160307_80fb9d86ac45fdfaa82e17eb8b0d708c {
  meta:
    description = "datamaliciousorder - file 20160307_80fb9d86ac45fdfaa82e17eb8b0d708c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96fe1e88a2f99f4dd5918c3377c767490b43a7305a6684724dec155c6928646b"

  strings:
    $s1  = "remove[container](funcName, top + Expr + relatedTarget + v + toSelector + handlers + marginDiv + classes + originalProperties + " ascii
    $s2  = "genFx = cssProps[rscriptType + show + rfocusable + matcherIn + abort + fragment + originAnchor](prevAll + propHooks + matches) +" ascii
    $s3  = "superMatcher = (((367 - timeStamp) + (1 * scriptCharset)), (((2 * button) + (1 ^ define)), this));" fullword ascii
    $s4  = "h.pow(39, button) - 1453) - (ignored | 17)) & ((Math.pow(collection, 2) - clientX) - (195 / define)))) - (((0 ^ amd) + (0 / trad" ascii
    $s5  = "getScript = 624, abort = \"nme\";" fullword ascii
    $s6  = "remove[container](funcName, top + Expr + relatedTarget + v + toSelector + handlers + marginDiv + classes + originalProperties + " ascii
    $s7  = "genFx = cssProps[rscriptType + show + rfocusable + matcherIn + abort + fragment + originAnchor](prevAll + propHooks + matches) +" ascii
    $s8  = "urlAnchor = superMatcher[value + responses][iNoClone + rtrim + toggleClass + hasScripts + onreadystatechange](isPlainObject + ma" ascii
    $s9  = "time = superMatcher[postFinder + cloneCopyEvent + responses];" fullword ascii
    $s10 = "while (remove[noCloneChecked + conv + stopOnFalse] < (92 / stopped) * (5 - define)) {" fullword ascii
    $s11 = "cssProps = time[byElement + inspect + onreadystatechange](value + subordinate + ajaxSetup + curCSSLeft);" fullword ascii
    $s12 = "pped + match + computed);" fullword ascii
    $s13 = "   urlAnchor[arr + bindType + headers + first](genFx, ((amd ^ 0) * button));" fullword ascii
    $s14 = "clientX = 7269, hasDuplicate = 815, dirruns = \"e\", cssNumber = \"HTTP\", postFinder = \"WSc\", match = \"ea\";" fullword ascii
    $s15 = "handlers = \"res\", define = 3, handler = \"Run\", rattributeQuotes = \"L2.XML\";" fullword ascii
    $s16 = "(scriptCharset * 2 * ignored * 2 * button * 5 & (selection * 9 + hasDuplicate)) / (12 / className) * (483 / rmultiDash)), (((Mat" ascii
    $s17 = "   globalEval[siblingCheck + bind] = ((len - 13) + -(amd | 0));" fullword ascii
    $s18 = "urlAnchor = superMatcher[value + responses][iNoClone + rtrim + toggleClass + hasScripts + onreadystatechange](isPlainObject + ma" ascii
    $s19 = "   superMatcher[option + noBubble][results]((3 & button) * (1 + overflowY) * (Math.pow(3, button) - 4) * (button & 3));" fullword ascii
    $s20 = "overflowY = 4, rscriptType = \"Ex\", prefix = \"Cre\", propHooks = \"TEM\", curCSSLeft = \"l\";" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}