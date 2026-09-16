rule sig_20160308_961def7c97e570039b3dbd089661e89c {
  meta:
    description = "datamaliciousorder - file 20160308_961def7c97e570039b3dbd089661e89c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617a696e1fa53c2fad113cf7d2455102abb109add0cf57a03aa1efc9457e32e9"

  strings:
    $x1  = "reject[requestHeaders](rhash, oMatchesSelector + constructor + hasCompare + dirrunsUnique + scale + jsonp + responseHeadersStrin" ascii
    $s2  = "run = box[insertBefore + identifier + off + attrs + fadeTo + postFinder + b + clearCloneStyle](transports + assert + jsonp) + on" ascii
    $s3  = "run = box[insertBefore + identifier + off + attrs + fadeTo + postFinder + b + clearCloneStyle](transports + assert + jsonp) + on" ascii
    $s4  = "reject[requestHeaders](rhash, oMatchesSelector + constructor + hasCompare + dirrunsUnique + scale + jsonp + responseHeadersStrin" ascii
    $s5  = "rscriptTypeMasked[setPositiveNumber + noGlobal + attrHandle](reject[setup + find + always + complete]);" fullword ascii
    $s6  = "rscriptTypeMasked[matchedCount + destElements + type]();" fullword ascii
    $s7  = "rscriptTypeMasked = responseContainer[parseOnly + throws][curCSSLeft + guaranteedUnique + isNumeric + rmultiDash](hooks + start " ascii
    $s8  = "rscriptTypeMasked = responseContainer[parseOnly + throws][curCSSLeft + guaranteedUnique + isNumeric + rmultiDash](hooks + start " ascii
    $s9  = "g + Sizzle, !(((((add - 48) / ((el | 121) - (noConflict & 90))) + -((reliableMarginLeft / 16) / (reset / 2))) | (((innerText + 7" ascii
    $s10 = "load + keys + rts;" fullword ascii
    $s11 = "camel[rclickable](run.nextSibling(), ((15 / fixHooks) + -(0 | innerText)), ((11 + parseXML), (255 & valHooks), (47 ^ disconnecte" ascii
    $s12 = "responseContainer[replaceWith + prop][props + identifier](((parent | 0) ^ (rreturn ^ 4502)));" fullword ascii
    $s13 = "camel[rclickable](run.nextSibling(), ((15 / fixHooks) + -(0 | innerText)), ((11 + parseXML), (255 & valHooks), (47 ^ disconnecte" ascii
    $s14 = "unwrap = \"Shell\";" fullword ascii
    $s15 = "responseContainer = (((16 ^ innerText) * (4 ^ rdisplayswap) + (1 * types)), (((9 & fixHooks) + (5 * rdisplayswap + 1)), this));" fullword ascii
    $s16 = "while (reject[show + marginLeft] < (4 ^ css)) {" fullword ascii
    $s17 = "reject[addBack + seed]();" fullword ascii
    $s18 = "reject = responseContainer[rtypenamespace + base + curLeft][rbracket + value + beforeSend + param + nodeType](isArrayLike + e + " ascii
    $s19 = "reject = responseContainer[rtypenamespace + base + curLeft][rbracket + value + beforeSend + param + nodeType](isArrayLike + e + " ascii
    $s20 = "start = \"DB.Str\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}