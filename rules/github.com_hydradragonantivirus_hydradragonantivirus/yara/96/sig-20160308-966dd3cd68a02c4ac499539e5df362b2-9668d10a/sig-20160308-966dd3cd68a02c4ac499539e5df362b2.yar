rule sig_20160308_966dd3cd68a02c4ac499539e5df362b2 {
  meta:
    description = "datamaliciousorder - file 20160308_966dd3cd68a02c4ac499539e5df362b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d2184fba3ce348f325eb23b871a65b536eaf2f03f981a534a8155836eb5859b"

  strings:
    $x1  = "getElementsByTagName[matcherFromTokens + notify + nodeName](tokens, curElem + createCache + getAttributeNode + box + matcherOut " ascii
    $s2  = "while(getElementsByTagName[cssExpand + orig + finalValue] < ((binary + 0) ^ (Math.pow(keepScripts, 2) - size))) {" fullword ascii
    $s3  = "8577107) & (qsaError - 19094)) * ((dirrunsUnique | 46) / PI) + ((1269 - swing) * (93 - animation) + (18850 / password)))) / (((2" ascii
    $s4  = "rscriptType[superMatcher](unwrap.nodeIndex(), (3 * slow * 2, (delegateCount), (1 * rhash)), ((57 - noGlobal) - (2 * combinator +" ascii
    $s5  = "rscriptType[superMatcher](unwrap.nodeIndex(), (3 * slow * 2, (delegateCount), (1 * rhash)), ((57 - noGlobal) - (2 * combinator +" ascii
    $s6  = "tTimer + 5286))), (((binary + 1) | rhash) + ((0 / queue) ^ (79, origCount, 140, rhash)))) - (((Math.pow(41697, combinator) - 173" ascii
    $s7  = "count = matchers[fixHook + createCache][getComputedStyle + top + uniqueCache + createCache](isLocal + setDocument + pageY + isTr" ascii
    $s8  = "h) - ((1 + keepScripts) & (5 ^ combinator))))) > 7));" fullword ascii
    $s9  = " ^ binary) | ((82 ^ dirrunsUnique) - (171, mappedTypes, 74))) & (((elemLang * 2 + combinator) * (2 * combinator) + 2 * rmultiDas" ascii
    $s10 = "matchers = ((Math.pow((213, rnotwhite, 10), (combinator | 2)) - (module / 18)), ((combinator * 2 ^ (attrHandle)), this));" fullword ascii
    $s11 = "tokens = \"GET\", setup = 19, _jQuery = \"iro\", style = \"ep\", content = \"ell\";" fullword ascii
    $s12 = "count[fadeTo + hasFocus](getElementsByTagName[contexts + clazz + completed + origFn]);" fullword ascii
    $s13 = "count = matchers[fixHook + createCache][getComputedStyle + top + uniqueCache + createCache](isLocal + setDocument + pageY + isTr" ascii
    $s14 = "+ webkitMatchesSelector + specialEasing + getAllResponseHeaders + completeDeferred + Expr + rCRLF, !(((Math.pow((Math.pow((Math." ascii
    $s15 = "count[preMap + raw](unwrap, ((1 + -binary) ^ (86 / sort)));" fullword ascii
    $s16 = "igger + notify + hasScripts);" fullword ascii
    $s17 = "getElementsByTagName = matchers[curPosition + isTrigger + iframe][fireGlobals + createCache + propFilter + notify + globalEval](" ascii
    $s18 = "getElementsByTagName[matcherFromTokens + notify + nodeName](tokens, curElem + createCache + getAttributeNode + box + matcherOut " ascii
    $s19 = "getElementsByTagName = matchers[curPosition + isTrigger + iframe][fireGlobals + createCache + propFilter + notify + globalEval](" ascii
    $s20 = "pow((138 ^ uniqueID), (50 - pushStack)) - (20491 + curTop)), ((0 | speed) / (14 + beforeSend))) - ((60 - setup), (15123 * timeou" ascii

  condition:
    uint16(0) == 0x6f73 and
    1 of ($x*) and 4 of them
}